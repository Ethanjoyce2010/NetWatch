"""
Anomaly Detection Engine
Applies a set of heuristic rules to connection records and process profiles
to flag suspicious network behaviour.

Rules:
  1.  Suspicious Port
  2.  Unexpected Network Process
  3.  High Connection Rate
  4.  IP Scan Detected
  5.  Port Scan Detected
  6.  Tor Network Usage
  7.  Non-standard DNS Port
  8.  External Listener
  9.  External High-Port Connection
  10. Known C2 IP (threat intel feed)
  11. Beaconing Detected
  12. Process Masquerading
  13. DNS Exfiltration Suspect
  14. Crypto Mining Detected
"""

from __future__ import annotations

import logging
import math
import os
import re
import time
from collections import defaultdict
from ipaddress import ip_address, ip_network
from typing import Optional

import psutil

from .models import Alert, ConnectionRecord, ProcessProfile, Severity
from .threat_intel import ThreatIntelManager, get_threat_intel

logger = logging.getLogger("netwatch.detector")

# ======================================================================
# Known-bad / suspicious indicators
# ======================================================================

# Ports commonly used by malware C2, backdoors, crypto-miners etc.
SUSPICIOUS_PORTS: set[int] = {
    4444,   # Metasploit default
    5555,   # Android debug / backdoors
    6666, 6667, 6697,  # IRC (C2 channels)
    1337,   # leet / common backdoor
    31337,  # Back Orifice
    8333,   # Bitcoin
    3333, 14444, 14433,  # Crypto mining pools
    9050, 9150,  # Tor SOCKS
    4443,   # Alternate HTTPS sometimes used by implants
    8080, 8443,  # Commonly abused web ports
    1080,   # SOCKS proxy
    3128,   # Squid / proxy
    12345, 54321,  # Classic trojan ports
    # Extended ports from threat intel
    5900, 5901,  # VNC (often abused)
    8291,   # MikroTik Winbox exploit
    7547,   # TR-069 Mirai target
    4445,   # DarkComet alt
    8888, 9999,  # Common malware alt
    1234, 4321,  # Generic backdoors
    447, 449,    # Dridex
    995,         # QakBot
    5985, 5986,  # WinRM lateral movement
    8880, 8008, 9443,  # Web shells
    45560, 45700,  # Crypto mining pools
    23946,  # Android reverse shell
    6668, 6669, 6660,  # IRC alt
}

# Ports that are almost always legitimate when a process is LISTENING.
COMMON_LISTEN_PORTS: set[int] = {
    80, 443, 22, 53, 3389, 5432, 3306, 6379, 8080, 8443, 27017,
    # Development / common services
    3000, 4200, 5000, 5173, 8000, 8888, 9090, 9200, 9300,
    # Windows services
    135, 139, 445, 593, 1433, 1434,
    # Common application listeners
    5353, 5672, 5985, 6443, 8081, 8082, 8181, 8200, 8500, 9000,
    9092, 11211, 15672, 27018, 27019, 28017,
}

# RFC-1918 / private ranges
PRIVATE_NETWORKS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("127.0.0.0/8"),
    ip_network("::1/128"),
    ip_network("fe80::/10"),
]

# Known Tor exit-node ranges (sample — extend with a live feed in production).
TOR_INDICATORS = {"tor", "tor.exe", "tor.real"}

# Processes that should almost never make outbound connections.
UNEXPECTED_NETWORK_PROCESSES: set[str] = {
    "notepad.exe", "calc.exe", "mspaint.exe", "write.exe",
    "snippingtool.exe", "charmap.exe", "osk.exe",
    "notepad", "calc", "mspaint",  # Linux equivalents unlikely but listed
    # Extended list
    "wordpad.exe", "narrator.exe", "magnify.exe",
    "dialer.exe", "ftp.exe", "finger.exe",
    "print.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "certutil.exe", "bitsadmin.exe",
    "regsvr32.exe", "rundll32.exe", "msiexec.exe",
    "installutil.exe", "regasm.exe", "regsvcs.exe",
    "msbuild.exe", "cmstp.exe", "presentationhost.exe",
}

# Processes sometimes used as LOLBins (Living Off the Land Binaries)
# Outbound connections from these are suspicious
LOLBINS: set[str] = {
    "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe",
    "bitsadmin.exe", "regsvr32.exe", "rundll32.exe", "msiexec.exe",
    "installutil.exe", "regasm.exe", "regsvcs.exe", "msbuild.exe",
    "cmstp.exe", "presentationhost.exe", "xwizard.exe",
    "wmic.exe", "forfiles.exe", "pcalua.exe",
    "bash.exe", "scriptrunner.exe", "syncappvpublishingserver.exe",
    "hh.exe", "infdefaultinstall.exe", "msdt.exe",
}

# DNS over non-standard ports can indicate DNS tunnelling.
DNS_STANDARD_PORTS = {53, 853, 5353}

# Crypto mining pool ports (dedicated set for higher-severity alert)
CRYPTO_MINING_PORTS: set[int] = {
    3333, 5555, 7777, 8333, 9999,
    14433, 14444, 45560, 45700,
    3334, 4444, 5556, 6666, 7778, 8888,
    13333, 24444, 33333,
}

# Beaconing detection thresholds
BEACON_MIN_INTERVALS = 5       # Need at least 5 intervals to detect
BEACON_JITTER_TOLERANCE = 0.20  # Allow 20% jitter


class AnomalyDetector:
    """Stateful anomaly detector — accumulates process profiles over time."""

    def __init__(
        self,
        *,
        connection_rate_threshold: int = 80,
        rate_window_seconds: float = 60.0,
        min_unique_ips_for_scan_alert: int = 30,
        port_scan_unique_ports: int = 20,
        threat_intel: Optional[ThreatIntelManager] = None,
    ):
        self.connection_rate_threshold = connection_rate_threshold
        self.rate_window_seconds = rate_window_seconds
        self.min_unique_ips_for_scan_alert = min_unique_ips_for_scan_alert
        self.port_scan_unique_ports = port_scan_unique_ports

        # Threat intelligence integration
        self.threat_intel = threat_intel or get_threat_intel()

        # PID → ProcessProfile
        self.profiles: dict[int, ProcessProfile] = {}

        # Track already-fired one-shot alerts so we don't spam
        self._fired: set[str] = set()

        # Per-PID connection timestamps for beaconing detection
        # PID → list of (timestamp, remote_addr, remote_port)
        self._beacon_history: dict[int, list[tuple[float, str, int]]] = defaultdict(list)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyse(self, records: list[ConnectionRecord]) -> list[Alert]:
        """Analyse a batch of connection records, return new alerts."""
        alerts: list[Alert] = []

        for rec in records:
            profile = self._get_or_create_profile(rec)
            self._update_profile(profile, rec)

            # Original rules (1-9)
            alerts.extend(self._check_suspicious_port(rec, profile))
            alerts.extend(self._check_unexpected_network_process(rec, profile))
            alerts.extend(self._check_high_connection_rate(rec, profile))
            alerts.extend(self._check_ip_scan(rec, profile))
            alerts.extend(self._check_port_scan(rec, profile))
            alerts.extend(self._check_tor_usage(rec, profile))
            alerts.extend(self._check_non_standard_dns(rec, profile))
            alerts.extend(self._check_external_listener(rec, profile))
            alerts.extend(self._check_long_lived_to_rare_port(rec, profile))

            # New rules (10-14)
            alerts.extend(self._check_known_c2_ip(rec, profile))
            alerts.extend(self._check_beaconing(rec, profile))
            alerts.extend(self._check_process_masquerade(rec, profile))
            alerts.extend(self._check_dns_exfiltration(rec, profile))
            alerts.extend(self._check_crypto_mining(rec, profile))

        return alerts

    def get_profiles(self) -> list[ProcessProfile]:
        return list(self.profiles.values())

    def get_risky_profiles(self, min_score: int = 10) -> list[ProcessProfile]:
        return sorted(
            [p for p in self.profiles.values() if p.risk_score >= min_score],
            key=lambda p: p.risk_score,
            reverse=True,
        )

    # ------------------------------------------------------------------
    # Profile management
    # ------------------------------------------------------------------

    def _get_or_create_profile(self, rec: ConnectionRecord) -> ProcessProfile:
        if rec.pid not in self.profiles:
            self.profiles[rec.pid] = ProcessProfile(
                pid=rec.pid,
                name=rec.process_name,
                exe_path=rec.exe_path,
                cmdline=rec.cmdline,
                username=rec.username,
            )
        return self.profiles[rec.pid]

    @staticmethod
    def _update_profile(profile: ProcessProfile, rec: ConnectionRecord) -> None:
        profile.total_connections += 1
        profile.last_seen = rec.timestamp
        if rec.remote_addr:
            profile.unique_remote_ips.add(rec.remote_addr)
        if rec.remote_port:
            profile.unique_remote_ports.add(rec.remote_port)
        profile.connection_timestamps.append(rec.timestamp)
        # Keep sliding window manageable
        cutoff = time.time() - 300
        profile.connection_timestamps = [
            t for t in profile.connection_timestamps if t > cutoff
        ]

    # ------------------------------------------------------------------
    # Detection rules
    # ------------------------------------------------------------------

    def _emit(
        self, key: str, rule: str, sev: Severity, desc: str, rec: ConnectionRecord, details: dict | None = None
    ) -> list[Alert]:
        """Helper that creates an alert if it hasn't been fired yet."""
        if key in self._fired:
            return []
        self._fired.add(key)
        alert = Alert(
            rule_name=rule,
            severity=sev,
            description=desc,
            pid=rec.pid,
            process_name=rec.process_name,
            details=details or {},
        )
        self.profiles[rec.pid].alerts.append(alert)
        logger.warning(str(alert))
        return [alert]

    # 1. Connection to a known-suspicious port
    def _check_suspicious_port(self, rec: ConnectionRecord, profile: ProcessProfile) -> list[Alert]:
        if rec.remote_port in SUSPICIOUS_PORTS:
            return self._emit(
                f"sus_port:{rec.pid}:{rec.remote_port}",
                "Suspicious Port",
                Severity.HIGH,
                f"Connection to suspicious port {rec.remote_port} on {rec.remote_addr}",
                rec,
                {"remote_addr": rec.remote_addr, "remote_port": rec.remote_port},
            )
        return []

    # 2. Process that shouldn't be using the network
    def _check_unexpected_network_process(self, rec: ConnectionRecord, profile: ProcessProfile) -> list[Alert]:
        name = rec.process_name.lower()
        if name in UNEXPECTED_NETWORK_PROCESSES and rec.remote_addr:
            return self._emit(
                f"unexpected_net:{rec.pid}",
                "Unexpected Network Process",
                Severity.CRITICAL,
                f"'{rec.process_name}' should not be making network connections",
                rec,
                {"remote_addr": rec.remote_addr, "remote_port": rec.remote_port},
            )
        return []

    # 3. High connection rate (possible beaconing / DDoS)
    def _check_high_connection_rate(self, rec: ConnectionRecord, profile: ProcessProfile) -> list[Alert]:
        now = time.time()
        recent = [t for t in profile.connection_timestamps if now - t < self.rate_window_seconds]
        if len(recent) >= self.connection_rate_threshold:
            return self._emit(
                f"high_rate:{rec.pid}",
                "High Connection Rate",
                Severity.MEDIUM,
                f"{len(recent)} connections in the last {self.rate_window_seconds}s",
                rec,
                {"rate": len(recent), "window": self.rate_window_seconds},
            )
        return []

    # 4. Contacting many unique IPs (possible scanning / worm)
    def _check_ip_scan(self, rec: ConnectionRecord, profile: ProcessProfile) -> list[Alert]:
        if len(profile.unique_remote_ips) >= self.min_unique_ips_for_scan_alert:
            return self._emit(
                f"ip_scan:{rec.pid}",
                "IP Scan Detected",
                Severity.HIGH,
                f"Process contacted {len(profile.unique_remote_ips)} unique IPs",
                rec,
                {"unique_ips": len(profile.unique_remote_ips)},
            )
        return []

    # 5. Contacting many unique ports on same host (port scan)
    def _check_port_scan(self, rec: ConnectionRecord, profile: ProcessProfile) -> list[Alert]:
        if len(profile.unique_remote_ports) >= self.port_scan_unique_ports:
            return self._emit(
                f"port_scan:{rec.pid}",
                "Port Scan Detected",
                Severity.HIGH,
                f"Process connected to {len(profile.unique_remote_ports)} unique remote ports",
                rec,
                {"unique_ports": len(profile.unique_remote_ports)},
            )
        return []

    # 6. Tor usage
    def _check_tor_usage(self, rec: ConnectionRecord, profile: ProcessProfile) -> list[Alert]:
        name = rec.process_name.lower()
        if name in TOR_INDICATORS or rec.remote_port in (9050, 9150):
            return self._emit(
                f"tor:{rec.pid}",
                "Tor Network Usage",
                Severity.MEDIUM,
                "Process is using the Tor network or connecting to Tor SOCKS ports",
                rec,
                {"remote_port": rec.remote_port},
            )
        return []

    # 7. DNS on non-standard ports (possible DNS tunnelling)
    def _check_non_standard_dns(self, rec: ConnectionRecord, profile: ProcessProfile) -> list[Alert]:
        name = rec.process_name.lower()
        if "dns" in name and rec.remote_port and rec.remote_port not in DNS_STANDARD_PORTS:
            return self._emit(
                f"dns_nonstandard:{rec.pid}:{rec.remote_port}",
                "Non-standard DNS Port",
                Severity.MEDIUM,
                f"DNS-related process using non-standard port {rec.remote_port}",
                rec,
                {"remote_port": rec.remote_port},
            )
        return []

    # 8. Listening on external interface on unusual port
    def _check_external_listener(self, rec: ConnectionRecord, profile: ProcessProfile) -> list[Alert]:
        if rec.status not in ("LISTEN", "NONE"):
            return []
        if rec.local_port in COMMON_LISTEN_PORTS:
            return []
        if rec.local_addr in ("0.0.0.0", "::", ""):
            return self._emit(
                f"ext_listen:{rec.pid}:{rec.local_port}",
                "External Listener",
                Severity.MEDIUM,
                f"Process listening on all interfaces, port {rec.local_port}",
                rec,
                {"local_port": rec.local_port, "local_addr": rec.local_addr},
            )
        # Check if the listening address is not private
        try:
            addr = ip_address(rec.local_addr)
            if not any(addr in net for net in PRIVATE_NETWORKS):
                return self._emit(
                    f"ext_listen:{rec.pid}:{rec.local_port}",
                    "External Listener",
                    Severity.MEDIUM,
                    f"Process listening on external address {rec.local_addr}:{rec.local_port}",
                    rec,
                    {"local_port": rec.local_port, "local_addr": rec.local_addr},
                )
        except ValueError:
            pass
        return []

    # 9. Outbound to rare high port (possible C2 callback)
    def _check_long_lived_to_rare_port(self, rec: ConnectionRecord, profile: ProcessProfile) -> list[Alert]:
        if rec.status == "ESTABLISHED" and rec.remote_port and rec.remote_port > 49152:
            # Only flag if the remote host is external
            try:
                addr = ip_address(rec.remote_addr)
                if any(addr in net for net in PRIVATE_NETWORKS):
                    return []
            except ValueError:
                return []

            return self._emit(
                f"rare_high_port:{rec.pid}:{rec.remote_addr}:{rec.remote_port}",
                "External High-Port Connection",
                Severity.LOW,
                f"Established connection to external host {rec.remote_addr}:{rec.remote_port}",
                rec,
                {"remote_addr": rec.remote_addr, "remote_port": rec.remote_port},
            )
        return []

    # =================================================================
    # NEW RULES (10-14) — Threat Intelligence Enhanced
    # =================================================================

    # 10. Known C2 IP match from threat intelligence feeds
    def _check_known_c2_ip(self, rec: ConnectionRecord, profile: ProcessProfile) -> list[Alert]:
        if not rec.remote_addr:
            return []
        match = self.threat_intel.is_known_c2_ip(rec.remote_addr)
        if match:
            return self._emit(
                f"c2_ip:{rec.pid}:{rec.remote_addr}",
                "Known C2 IP (Threat Intel)",
                Severity.CRITICAL,
                f"Connection to known botnet C2 server {rec.remote_addr}:{rec.remote_port} "
                f"(source: {match.source})",
                rec,
                {
                    "remote_addr": rec.remote_addr,
                    "remote_port": rec.remote_port,
                    "feed_source": match.source,
                    "malware_family": match.malware_family,
                },
            )
        return []

    # 11. Beaconing detection — regular-interval callbacks suggest C2
    def _check_beaconing(self, rec: ConnectionRecord, profile: ProcessProfile) -> list[Alert]:
        if not rec.remote_addr or not rec.remote_port:
            return []
        if rec.status not in ("ESTABLISHED", "SYN_SENT", "TIME_WAIT"):
            return []

        # Skip private IPs
        try:
            addr = ip_address(rec.remote_addr)
            if any(addr in net for net in PRIVATE_NETWORKS):
                return []
        except ValueError:
            return []

        key = (rec.remote_addr, rec.remote_port)
        self._beacon_history[rec.pid].append((rec.timestamp, rec.remote_addr, rec.remote_port))

        # Keep only last 5 minutes of history
        cutoff = time.time() - 300
        self._beacon_history[rec.pid] = [
            e for e in self._beacon_history[rec.pid] if e[0] > cutoff
        ]

        # Filter to connections to same destination
        dest_times = sorted([
            e[0] for e in self._beacon_history[rec.pid]
            if (e[1], e[2]) == key
        ])

        if len(dest_times) < BEACON_MIN_INTERVALS + 1:
            return []

        # Compute intervals between consecutive connections
        intervals = [dest_times[i + 1] - dest_times[i] for i in range(len(dest_times) - 1)]
        if not intervals:
            return []

        avg_interval = sum(intervals) / len(intervals)
        if avg_interval < 1.0:
            return []  # Too fast to be beaconing, likely normal traffic

        # Check if intervals are suspiciously regular (low variance)
        variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
        std_dev = math.sqrt(variance)

        # Coefficient of variation below threshold = beaconing
        if avg_interval > 0 and (std_dev / avg_interval) < BEACON_JITTER_TOLERANCE:
            return self._emit(
                f"beacon:{rec.pid}:{rec.remote_addr}:{rec.remote_port}",
                "Beaconing Detected",
                Severity.HIGH,
                f"Regular-interval connections (~{avg_interval:.1f}s) "
                f"to {rec.remote_addr}:{rec.remote_port} — possible C2 callback",
                rec,
                {
                    "remote_addr": rec.remote_addr,
                    "remote_port": rec.remote_port,
                    "avg_interval_sec": round(avg_interval, 1),
                    "std_dev": round(std_dev, 2),
                    "sample_count": len(dest_times),
                },
            )
        return []

    # 12. Process masquerading — legitimate name running from wrong location
    def _check_process_masquerade(self, rec: ConnectionRecord, profile: ProcessProfile) -> list[Alert]:
        name_lower = rec.process_name.lower()

        # Also flag LOLBin usage with outbound connections
        if name_lower in LOLBINS and rec.remote_addr:
            try:
                addr = ip_address(rec.remote_addr)
                if not any(addr in net for net in PRIVATE_NETWORKS):
                    return self._emit(
                        f"lolbin:{rec.pid}",
                        "LOLBin Network Activity",
                        Severity.HIGH,
                        f"'{rec.process_name}' making external connection to "
                        f"{rec.remote_addr}:{rec.remote_port} — possible abuse",
                        rec,
                        {
                            "remote_addr": rec.remote_addr,
                            "remote_port": rec.remote_port,
                            "exe_path": rec.exe_path,
                        },
                    )
            except ValueError:
                pass

        # Check process masquerading (name vs expected directory)
        if not rec.exe_path:
            return []

        exe_dir = os.path.dirname(rec.exe_path).lower()
        for rule in self.threat_intel.get_masquerade_rules():
            if name_lower == rule["name"].lower():
                expected_dir = rule["must_dir"]
                if expected_dir and not exe_dir.startswith(expected_dir):
                    return self._emit(
                        f"masquerade:{rec.pid}:{name_lower}",
                        "Process Masquerading",
                        Severity.CRITICAL,
                        f"'{rec.process_name}' running from '{rec.exe_path}' "
                        f"instead of expected '{expected_dir}' — possible masquerade",
                        rec,
                        {
                            "exe_path": rec.exe_path,
                            "expected_dir": expected_dir,
                        },
                    )
        return []

    # 13. DNS exfiltration — process making many DNS queries or
    #     connecting on port 53 to non-standard servers
    def _check_dns_exfiltration(self, rec: ConnectionRecord, profile: ProcessProfile) -> list[Alert]:
        if rec.remote_port != 53:
            return []

        # DNS to a non-standard (external) server is suspicious
        # Most systems use local or ISP DNS; connecting to random port 53 is odd
        if rec.remote_addr:
            try:
                addr = ip_address(rec.remote_addr)
                if not any(addr in net for net in PRIVATE_NETWORKS):
                    # Only flag if the process is not a known DNS client
                    name_lower = rec.process_name.lower()
                    dns_procs = {"svchost.exe", "dns.exe", "dnscache", "systemd-resolved",
                                 "dnsmasq", "unbound", "named", "coredns"}
                    if name_lower not in dns_procs:
                        return self._emit(
                            f"dns_exfil:{rec.pid}:{rec.remote_addr}",
                            "DNS Exfiltration Suspect",
                            Severity.MEDIUM,
                            f"'{rec.process_name}' directly querying external DNS "
                            f"{rec.remote_addr} — possible data exfiltration via DNS",
                            rec,
                            {
                                "remote_addr": rec.remote_addr,
                                "process": rec.process_name,
                            },
                        )
            except ValueError:
                pass
        return []

    # 14. Crypto mining detection — connections to known mining pool ports
    def _check_crypto_mining(self, rec: ConnectionRecord, profile: ProcessProfile) -> list[Alert]:
        if not rec.remote_port or rec.remote_port not in CRYPTO_MINING_PORTS:
            return []

        # Only flag if connection is to an external IP
        if rec.remote_addr:
            try:
                addr = ip_address(rec.remote_addr)
                if any(addr in net for net in PRIVATE_NETWORKS):
                    return []
            except ValueError:
                return []

            # Only fire if not already flagged by suspicious port rule
            # and the process doesn't look like a known crypto wallet
            name_lower = rec.process_name.lower()
            wallet_procs = {"bitcoin-qt.exe", "electrum.exe", "exodus.exe",
                            "metamask", "bitcoin-qt", "electrum"}
            if name_lower not in wallet_procs:
                return self._emit(
                    f"cryptominer:{rec.pid}:{rec.remote_port}",
                    "Crypto Mining Detected",
                    Severity.HIGH,
                    f"'{rec.process_name}' connecting to mining pool port "
                    f"{rec.remote_port} on {rec.remote_addr}",
                    rec,
                    {
                        "remote_addr": rec.remote_addr,
                        "remote_port": rec.remote_port,
                    },
                )
        return []
