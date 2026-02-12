"""
Threat Intelligence Feed Manager
Downloads, caches, and queries IOC feeds from public threat intelligence sources.

Feeds (no auth required — auto-updated):
  - Feodo Tracker:  Botnet C2 IP blocklist
  - SSLBL:          SSL C2 IP blacklist
  - URLhaus:        Active malware distribution hosts

Static definitions (always available offline):
  - Known C2 IP ranges, malicious domains, suspicious DLL names,
    malware hash patterns, APT indicators

Optional API lookups (requires free abuse.ch auth key):
  - MalwareBazaar:  SHA256 hash ↔ malware family lookup
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import URLError

logger = logging.getLogger("netwatch.threat_intel")

# ======================================================================
# Feed configuration
# ======================================================================

CACHE_DIR = Path(os.environ.get("NETWATCH_CACHE", "")) or (
    Path.home() / ".netwatch" / "feeds"
)
CACHE_MAX_AGE_SECONDS = 3600  # Re-download feeds if older than 1 hour

FEEDS: dict[str, dict] = {
    "feodo_c2_ips": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "description": "Feodo Tracker — Botnet C2 IP blocklist (Dridex, Emotet, TrickBot, QakBot)",
        "parser": "_parse_feodo",
        "cache_file": "feodo_c2_ips.txt",
    },
    "sslbl_c2_ips": {
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
        "description": "SSLBL — SSL Botnet C2 IP blacklist",
        "parser": "_parse_sslbl",
        "cache_file": "sslbl_c2_ips.csv",
    },
    "urlhaus_hosts": {
        "url": "https://urlhaus.abuse.ch/downloads/text_online/",
        "description": "URLhaus — Active malware distribution URLs",
        "parser": "_parse_urlhaus",
        "cache_file": "urlhaus_hosts.txt",
    },
}

# ======================================================================
# Static threat intelligence definitions (always available offline)
# ======================================================================

# --- Known C2 / malicious IPs (curated from public reports) ---
STATIC_C2_IPS: set[str] = set()
# Common sinkholes / known-bad ranges are NOT included to avoid FPs.
# This set is populated by feed downloads; static entries are reserved
# for well-known, long-lived C2 infrastructure.

# --- Known malicious domains & patterns ---
KNOWN_MALICIOUS_DOMAINS: set[str] = {
    # Cobalt Strike team server defaults
    "cloudfront-us-east.com",
    "jquery-min.us", "jquery-cdn.online",
    # Common C2 redirectors
    "windowsupdatecdn.com", "microsoftupdate.club",
    "office365update.club", "outlook-update.online",
    # Emotet / TrickBot infrastructure patterns
    "update-microsoft.com", "security-microsoft.com",
    # Generic phishing / malware domains
    "login-verify.com", "account-verify.net",
    "secure-login-portal.com", "verify-identity.net",
}

# Regex patterns that match DGA (Domain Generation Algorithm) style domains
DGA_PATTERNS: list[re.Pattern] = [
    # Long strings of consonants (no vowels for 5+ chars)
    re.compile(r"[bcdfghjklmnpqrstvwxyz]{6,}", re.IGNORECASE),
    # Alternating random chars with numbers
    re.compile(r"^[a-z]{2,3}\d[a-z]{2,3}\d[a-z]{2,3}", re.IGNORECASE),
    # Very long subdomain (>20 chars of alphanumeric)
    re.compile(r"^[a-z0-9]{20,}\.", re.IGNORECASE),
]

# --- Extended suspicious ports ---
EXTENDED_SUSPICIOUS_PORTS: set[int] = {
    # RATs (Remote Access Trojans)
    4444,   # Metasploit default
    5555,   # Android debug / DarkComet
    1337,   # leet / generic backdoor
    31337,  # Back Orifice
    12345, 54321,  # NetBus, classic trojans
    23946,  # Android reverse shell
    5900, 5901,  # VNC (often abused)
    # IRC C2
    6666, 6667, 6697, 6668, 6669,
    # Crypto miners
    3333, 8333, 14444, 14433, 45560, 45700,
    # Tor
    9050, 9150, 9001, 9030,
    # Additional C2 / backdoor ports
    4443,   # Alternate HTTPS implants
    8291,   # MikroTik Winbox (exploit target)
    7547,   # TR-069 (Mirai target)
    2222,   # SSH alternate (often brute-forced)
    4445,   # Darkcomet alt
    6660,   # IRC alt
    8888,   # Common malware alt
    9999,   # Trojan port
    1234,   # Generic backdoor
    4321,   # Generic backdoor
    3389,   # RDP (suspicious if outbound)
    # Web shells / C2 HTTP
    8880, 8008, 9443,
    # Known malware families
    447,    # Dridex
    449,    # Dridex
    902,    # VMware (abused by APTs)
    995,    # QakBot
    3268,   # LDAP (lateral movement)
    5985, 5986,  # WinRM
    # Proxy / tunnel
    1080,   # SOCKS
    3128,   # Squid
    8118,   # Privoxy
    10080,  # Amanda / proxy
}

# --- Known malicious DLL names (extended) ---
EXTENDED_SUSPICIOUS_DLLS: set[str] = {
    # ---- Credential stealers / Mimikatz ----
    "mimilib.dll", "mimidrv.sys", "sekurlsa.dll", "kiwi.dll",
    "wce_x64.dll", "wce_x86.dll", "passcape.dll",
    # ---- Cobalt Strike ----
    "beacon.dll", "pivot.dll", "sleeve.dll", "artifact.dll",
    "bypass.dll", "drone.dll",
    # ---- Metasploit / Meterpreter ----
    "metsrv.dll", "ext_server_stdapi.dll", "ext_server_priv.dll",
    "ext_server_kiwi.dll", "ext_server_sniffer.dll",
    # ---- Reflective injection ----
    "reflective.dll", "reflectiveloader.dll", "rdll.dll",
    "reflective_dll.dll", "rdi.dll",
    # ---- Process injection / hollowing ----
    "hollow.dll", "runpe.dll", "inject.dll", "injector.dll",
    "shellcode.dll", "stage.dll", "stager.dll",
    # ---- Proxy / tunnel ----
    "proxydll.dll", "tunnel.dll", "socks.dll", "chisel.dll",
    "plink.dll", "frpc.dll",
    # ---- Persistence ----
    "persistence.dll", "startup.dll", "autorun.dll",
    # ---- Generic malware indicators ----
    "payload.dll", "hook.dll", "hooker.dll", "evil.dll",
    "malware.dll", "backdoor.dll", "shell.dll", "reverse.dll",
    "loader.dll", "dropper.dll", "downloader.dll",
    "keylog.dll", "keylogger.dll", "stealer.dll",
    "rat.dll", "rootkit.dll", "ransom.dll",
    # ---- Known malware families ----
    "emotet.dll", "trickbot.dll", "qbot.dll", "qakbot.dll",
    "icedid.dll", "cobint.dll", "dridex.dll", "ursnif.dll",
    "hancitor.dll", "bumblebee.dll", "bazar.dll", "bazarloader.dll",
    "pikabot.dll", "darkgate.dll", "asyncrat.dll",
    "remcos.dll", "njrat.dll", "warzone.dll", "redline.dll",
    "raccoon.dll", "vidar.dll", "lumma.dll", "stealc.dll",
    "amadey.dll", "smokeloader.dll", "systembc.dll",
    "solarmarker.dll", "formbook.dll", "xloader.dll",
    "agenttesla.dll", "snakekeylogger.dll",
    "latrodectus.dll", "matanbuchus.dll",
    # ---- Side-loading / hijack names (when NOT in system dir) ----
    "version.dll", "userenv.dll", "winhttp.dll", "dbghelp.dll",
    "crypt32.dll", "msimg32.dll", "cryptsp.dll",
    "dwmapi.dll", "uxtheme.dll", "propsys.dll", "profapi.dll",
    "WTSAPI32.dll", "wtsapi32.dll",
    # ---- Known APT tools ----
    "plugx.dll", "shadowpad.dll", "winnti.dll",
    "cobaltstrike.dll", "nighthawk.dll", "bruteratel.dll",
    "sliver.dll", "havoc.dll", "mythic.dll",
}

# --- Process name patterns that indicate masquerading ---
MASQUERADE_PATTERNS: list[dict] = [
    # Legitimate name → suspicious indicators
    {"name": "svchost.exe", "must_parent": "services.exe",
     "must_dir": r"c:\windows\system32"},
    {"name": "csrss.exe", "must_parent": "smss.exe",
     "must_dir": r"c:\windows\system32"},
    {"name": "lsass.exe", "must_parent": "wininit.exe",
     "must_dir": r"c:\windows\system32"},
    {"name": "winlogon.exe", "must_parent": "smss.exe",
     "must_dir": r"c:\windows\system32"},
    {"name": "explorer.exe", "must_parent": None,
     "must_dir": r"c:\windows"},
    {"name": "taskhostw.exe", "must_parent": "svchost.exe",
     "must_dir": r"c:\windows\system32"},
    {"name": "dllhost.exe", "must_parent": "svchost.exe",
     "must_dir": r"c:\windows\system32"},
    {"name": "conhost.exe", "must_parent": None,
     "must_dir": r"c:\windows\system32"},
    {"name": "RuntimeBroker.exe", "must_parent": "svchost.exe",
     "must_dir": r"c:\windows\system32"},
]

# --- Known malware file-hash prefixes / families for display ---
MALWARE_FAMILIES: dict[str, str] = {
    "emotet": "Emotet — Banking trojan / loader, spread via malspam",
    "trickbot": "TrickBot — Modular banking trojan, often precedes ransomware",
    "qakbot": "QakBot — Banking trojan / initial access broker",
    "dridex": "Dridex — Banking trojan delivered via macro-laced documents",
    "icedid": "IcedID — Banking trojan / loader, PDF/OneNote lures",
    "cobalt_strike": "Cobalt Strike — Commercial red team tool, heavily abused",
    "metasploit": "Metasploit — Open-source penetration testing framework",
    "mimikatz": "Mimikatz — Credential dumping tool",
    "remcos": "Remcos — Commercial RAT abused by threat actors",
    "asyncrat": "AsyncRAT — Open-source .NET RAT",
    "njrat": "NjRAT — .NET RAT popular in Middle East campaigns",
    "darkgate": "DarkGate — Loader/RAT with credential theft capabilities",
    "pikabot": "PikaBot — Modular loader, successor to QakBot operations",
    "lumma": "Lumma Stealer — Information stealer sold as MaaS",
    "redline": "RedLine — Information stealer targeting browsers/wallets",
    "raccoon": "Raccoon Stealer — MaaS information stealer",
    "vidar": "Vidar — Information stealer forked from Arkei",
    "smokeloader": "SmokeLoader — Modular loader/backdoor",
    "systembc": "SystemBC — Proxy bot used as C2 channel",
    "bumblebee": "Bumblebee — Loader replacing BazarLoader",
    "latrodectus": "Latrodectus — IcedID successor loader",
    "bruteratel": "Brute Ratel — Commercial C2 framework",
    "sliver": "Sliver — Open-source C2 framework by BishopFox",
    "havoc": "Havoc — Open-source C2 framework",
    "plugx": "PlugX — RAT associated with Chinese APT groups",
    "shadowpad": "ShadowPad — Modular backdoor linked to APT41",
    "formbook": "Formbook/XLoader — Form-grabber and info-stealer",
    "agenttesla": "Agent Tesla — .NET keylogger / info-stealer",
    "stealc": "StealC — Information stealer sold as MaaS",
    "amadey": "Amadey — Loader botnet",
    "warzone": "WarzoneRAT — Commercial RAT (AVE_MARIA)",
}

# ======================================================================
# Data classes
# ======================================================================


@dataclass
class FeedStatus:
    """Status of a single threat intelligence feed."""
    name: str
    description: str
    url: str
    last_updated: Optional[datetime] = None
    entry_count: int = 0
    error: Optional[str] = None
    cache_path: Optional[str] = None


@dataclass
class IOCMatch:
    """Result of an IOC lookup."""
    indicator: str
    indicator_type: str  # "ip", "domain", "hash", "dll"
    source: str
    malware_family: Optional[str] = None
    description: Optional[str] = None
    confidence: str = "high"  # "high", "medium", "low"
    first_seen: Optional[str] = None


# ======================================================================
# Main class
# ======================================================================


class ThreatIntelManager:
    """Downloads, caches and queries threat intelligence feeds."""

    def __init__(self, cache_dir: Optional[Path] = None, api_key: Optional[str] = None):
        self.cache_dir = cache_dir or CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.api_key = api_key or os.environ.get("ABUSE_CH_API_KEY")

        # In-memory IOC sets (populated by update_feeds or load_cache)
        self.c2_ips: set[str] = set(STATIC_C2_IPS)
        self.malicious_domains: set[str] = set(KNOWN_MALICIOUS_DOMAINS)
        self.malicious_urls: set[str] = set()
        self.malicious_hashes: dict[str, str] = {}  # hash → family/description

        self._feed_statuses: dict[str, FeedStatus] = {}

        # Try to load cached feeds on init
        self._load_all_caches()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def update_feeds(self, quiet: bool = False) -> dict[str, FeedStatus]:
        """Download all feeds and update the in-memory IOC sets."""
        for feed_name, feed_cfg in FEEDS.items():
            status = FeedStatus(
                name=feed_name,
                description=feed_cfg["description"],
                url=feed_cfg["url"],
                cache_path=str(self.cache_dir / feed_cfg["cache_file"]),
            )
            try:
                if not quiet:
                    logger.info("Updating feed: %s", feed_name)
                raw = self._download(feed_cfg["url"])
                cache_path = self.cache_dir / feed_cfg["cache_file"]
                cache_path.write_text(raw, encoding="utf-8")

                # Write metadata
                meta = {"updated": datetime.now(timezone.utc).isoformat(), "url": feed_cfg["url"]}
                meta_path = cache_path.with_suffix(cache_path.suffix + ".meta")
                meta_path.write_text(json.dumps(meta), encoding="utf-8")

                parser = getattr(self, feed_cfg["parser"])
                count = parser(raw)
                status.entry_count = count
                status.last_updated = datetime.now(timezone.utc)
                if not quiet:
                    logger.info("  -> %d entries loaded from %s", count, feed_name)

            except Exception as exc:
                status.error = str(exc)
                if not quiet:
                    logger.warning("Failed to update %s: %s", feed_name, exc)

            self._feed_statuses[feed_name] = status

        return self._feed_statuses

    def get_feed_status(self) -> dict[str, FeedStatus]:
        """Return status of all feeds."""
        # Refresh status from cache if empty
        if not self._feed_statuses:
            for feed_name, feed_cfg in FEEDS.items():
                cache_path = self.cache_dir / feed_cfg["cache_file"]
                meta_path = cache_path.with_suffix(cache_path.suffix + ".meta")
                status = FeedStatus(
                    name=feed_name,
                    description=feed_cfg["description"],
                    url=feed_cfg["url"],
                    cache_path=str(cache_path),
                )
                if meta_path.exists():
                    try:
                        meta = json.loads(meta_path.read_text(encoding="utf-8"))
                        status.last_updated = datetime.fromisoformat(meta["updated"])
                    except Exception:
                        pass
                self._feed_statuses[feed_name] = status
        return self._feed_statuses

    def is_known_c2_ip(self, ip: str) -> Optional[IOCMatch]:
        """Check if an IP is in the C2 blocklist."""
        ip_clean = ip.strip()
        if ip_clean in self.c2_ips:
            return IOCMatch(
                indicator=ip_clean,
                indicator_type="ip",
                source="abuse.ch feeds",
                description="Known botnet C2 server",
                confidence="high",
            )
        return None

    def is_known_malicious_domain(self, domain: str) -> Optional[IOCMatch]:
        """Check if a domain matches known malicious domains or DGA patterns."""
        domain_lower = domain.lower().strip()

        # Direct match
        if domain_lower in self.malicious_domains:
            return IOCMatch(
                indicator=domain_lower,
                indicator_type="domain",
                source="static definitions",
                description="Known malicious domain",
                confidence="high",
            )

        # Check if it's a subdomain of a known-bad domain
        for bad_domain in self.malicious_domains:
            if domain_lower.endswith("." + bad_domain):
                return IOCMatch(
                    indicator=domain_lower,
                    indicator_type="domain",
                    source="static definitions",
                    description=f"Subdomain of known malicious domain {bad_domain}",
                    confidence="high",
                )

        # DGA pattern check
        # Extract the main domain part (before TLD)
        parts = domain_lower.split(".")
        if len(parts) >= 2:
            main_part = parts[0] if len(parts) == 2 else ".".join(parts[:-2])
            for pattern in DGA_PATTERNS:
                if pattern.search(main_part):
                    return IOCMatch(
                        indicator=domain_lower,
                        indicator_type="domain",
                        source="DGA heuristic",
                        description="Domain name matches DGA pattern",
                        confidence="medium",
                    )

        return None

    def is_known_malicious_dll(self, dll_name: str) -> Optional[IOCMatch]:
        """Check if a DLL name is in the extended suspicious DLL list."""
        name_lower = dll_name.lower().strip()
        if name_lower in EXTENDED_SUSPICIOUS_DLLS:
            return IOCMatch(
                indicator=name_lower,
                indicator_type="dll",
                source="static definitions",
                description="Known malicious or suspicious DLL name",
                confidence="medium",
            )
        return None

    def check_file_hash(self, file_path: str) -> Optional[IOCMatch]:
        """Compute SHA256 of a file and check against known malicious hashes."""
        try:
            sha256 = self._sha256_file(file_path)
            if sha256 in self.malicious_hashes:
                return IOCMatch(
                    indicator=sha256,
                    indicator_type="hash",
                    source="local feed cache",
                    malware_family=self.malicious_hashes[sha256],
                    description=f"File matches known malware: {self.malicious_hashes[sha256]}",
                    confidence="high",
                )
        except (OSError, PermissionError):
            pass
        return None

    def lookup_hash_online(self, sha256: str) -> Optional[IOCMatch]:
        """Query MalwareBazaar API for a hash (requires API key)."""
        if not self.api_key:
            return None
        try:
            data = f"query=get_info&hash={sha256}".encode()
            req = Request(
                "https://mb-api.abuse.ch/api/v1/",
                data=data,
                headers={
                    "Auth-Key": self.api_key,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            with urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read().decode())
                if result.get("query_status") == "hash_not_found":
                    return None
                if "data" in result and result["data"]:
                    entry = result["data"][0] if isinstance(result["data"], list) else result["data"]
                    family = entry.get("signature", "Unknown")
                    return IOCMatch(
                        indicator=sha256,
                        indicator_type="hash",
                        source="MalwareBazaar",
                        malware_family=family,
                        description=f"MalwareBazaar: {family} ({entry.get('file_type', 'unknown')} file)",
                        confidence="high",
                        first_seen=entry.get("first_seen"),
                    )
        except Exception as exc:
            logger.debug("MalwareBazaar lookup failed: %s", exc)
        return None

    def get_malware_info(self, family_key: str) -> Optional[str]:
        """Get a human-readable description of a malware family."""
        return MALWARE_FAMILIES.get(family_key.lower())

    def get_suspicious_ports(self) -> set[int]:
        """Return the extended set of suspicious ports."""
        return set(EXTENDED_SUSPICIOUS_PORTS)

    def get_suspicious_dlls(self) -> set[str]:
        """Return the extended set of suspicious DLL names."""
        return set(EXTENDED_SUSPICIOUS_DLLS)

    def get_masquerade_rules(self) -> list[dict]:
        """Return process masquerade detection rules."""
        return list(MASQUERADE_PATTERNS)

    # ------------------------------------------------------------------
    # Feed parsers
    # ------------------------------------------------------------------

    def _parse_feodo(self, raw: str) -> int:
        """Parse Feodo Tracker IP blocklist (one IP per line, # comments)."""
        count = 0
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            self.c2_ips.add(line)
            count += 1
        return count

    def _parse_sslbl(self, raw: str) -> int:
        """Parse SSLBL CSV: Firstseen,DstIP,DstPort"""
        count = 0
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) >= 2:
                ip = parts[1].strip()
                # Validate it looks like an IP
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                    self.c2_ips.add(ip)
                    count += 1
        return count

    def _parse_urlhaus(self, raw: str) -> int:
        """Parse URLhaus text file of active malware URLs."""
        count = 0
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            self.malicious_urls.add(line)
            # Also extract domain/IP from URL for connection matching
            try:
                # Extract host from URL
                host = line.split("//", 1)[-1].split("/", 1)[0].split(":")[0]
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
                    self.c2_ips.add(host)
                else:
                    self.malicious_domains.add(host.lower())
                count += 1
            except Exception:
                pass
        return count

    # ------------------------------------------------------------------
    # Cache management
    # ------------------------------------------------------------------

    def _load_all_caches(self) -> None:
        """Load all cached feeds from disk."""
        for feed_name, feed_cfg in FEEDS.items():
            cache_path = self.cache_dir / feed_cfg["cache_file"]
            if cache_path.exists():
                try:
                    raw = cache_path.read_text(encoding="utf-8")
                    parser = getattr(self, feed_cfg["parser"])
                    parser(raw)
                    logger.debug("Loaded cached feed: %s", feed_name)
                except Exception as exc:
                    logger.debug("Failed to load cache %s: %s", feed_name, exc)

    def needs_update(self) -> bool:
        """Check if any feed cache is missing or stale."""
        for feed_cfg in FEEDS.values():
            cache_path = self.cache_dir / feed_cfg["cache_file"]
            if not cache_path.exists():
                return True
            age = time.time() - cache_path.stat().st_mtime
            if age > CACHE_MAX_AGE_SECONDS:
                return True
        return False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _download(url: str, timeout: int = 30) -> str:
        """Download a URL and return text content."""
        req = Request(url, headers={"User-Agent": "NetWatch/1.0 (github.com/Ethanjoyce2010/NetWatch)"})
        with urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")

    @staticmethod
    def _sha256_file(path: str) -> str:
        """Compute SHA256 hash of a file."""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()


# ======================================================================
# Convenience singleton
# ======================================================================

_instance: Optional[ThreatIntelManager] = None


def get_threat_intel() -> ThreatIntelManager:
    """Return a module-level singleton ThreatIntelManager."""
    global _instance
    if _instance is None:
        _instance = ThreatIntelManager()
    return _instance
