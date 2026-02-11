"""
Anomaly Detection Engine
Applies a set of heuristic rules to connection records and process profiles
to flag suspicious network behaviour.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from ipaddress import ip_address, ip_network
from typing import Optional

from .models import Alert, ConnectionRecord, ProcessProfile, Severity

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
}

# Ports that are almost always legitimate when a process is LISTENING.
COMMON_LISTEN_PORTS: set[int] = {
    80, 443, 22, 53, 3389, 5432, 3306, 6379, 8080, 8443, 27017,
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
}

# DNS over non-standard ports can indicate DNS tunnelling.
DNS_STANDARD_PORTS = {53, 853, 5353}


class AnomalyDetector:
    """Stateful anomaly detector — accumulates process profiles over time."""

    def __init__(
        self,
        *,
        connection_rate_threshold: int = 50,
        rate_window_seconds: float = 60.0,
        min_unique_ips_for_scan_alert: int = 25,
        port_scan_unique_ports: int = 15,
    ):
        self.connection_rate_threshold = connection_rate_threshold
        self.rate_window_seconds = rate_window_seconds
        self.min_unique_ips_for_scan_alert = min_unique_ips_for_scan_alert
        self.port_scan_unique_ports = port_scan_unique_ports

        # PID → ProcessProfile
        self.profiles: dict[int, ProcessProfile] = {}

        # Track already-fired one-shot alerts so we don't spam
        self._fired: set[str] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyse(self, records: list[ConnectionRecord]) -> list[Alert]:
        """Analyse a batch of connection records, return new alerts."""
        alerts: list[Alert] = []

        for rec in records:
            profile = self._get_or_create_profile(rec)
            self._update_profile(profile, rec)

            alerts.extend(self._check_suspicious_port(rec, profile))
            alerts.extend(self._check_unexpected_network_process(rec, profile))
            alerts.extend(self._check_high_connection_rate(rec, profile))
            alerts.extend(self._check_ip_scan(rec, profile))
            alerts.extend(self._check_port_scan(rec, profile))
            alerts.extend(self._check_tor_usage(rec, profile))
            alerts.extend(self._check_non_standard_dns(rec, profile))
            alerts.extend(self._check_external_listener(rec, profile))
            alerts.extend(self._check_long_lived_to_rare_port(rec, profile))

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
