"""
Network Statistics Summary — connection breakdown and top-talker analysis.

Provides a quick overview of:
  • Total connections / unique remote IPs / unique remote ports
  • Protocol breakdown (TCP vs UDP)
  • Connection state breakdown (ESTABLISHED, LISTEN, TIME_WAIT, etc.)
  • Top-N remote IPs by connection count
  • Top-N processes by connection count
  • Top-N remote ports by connection count
"""

from __future__ import annotations

import sys
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

from .models import ConnectionRecord, ProcessProfile

# ANSI helpers (same palette as reporter.py)
_CYAN = "\033[96m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_WHITE = "\033[97m"
_DIM = "\033[2m"
_BOLD = "\033[1m"
_RESET = "\033[0m"


@dataclass
class NetworkStats:
    """Computed network statistics from a snapshot."""

    total_connections: int = 0
    unique_remote_ips: int = 0
    unique_remote_ports: int = 0
    unique_processes: int = 0

    tcp_count: int = 0
    udp_count: int = 0

    state_counts: dict[str, int] = field(default_factory=dict)

    top_remote_ips: list[tuple[str, int]] = field(default_factory=list)
    top_processes: list[tuple[str, int, int]] = field(default_factory=list)  # (name, pid, count)
    top_remote_ports: list[tuple[int, int]] = field(default_factory=list)

    listen_count: int = 0
    established_count: int = 0
    external_count: int = 0
    internal_count: int = 0


def compute_stats(
    records: list[ConnectionRecord],
    profiles: Optional[list[ProcessProfile]] = None,
    top_n: int = 10,
) -> NetworkStats:
    """Compute network statistics from connection records."""
    stats = NetworkStats()
    stats.total_connections = len(records)

    remote_ips: set[str] = set()
    remote_ports: set[int] = set()
    pids: set[int] = set()

    ip_counter: Counter[str] = Counter()
    port_counter: Counter[int] = Counter()
    proc_counter: Counter[tuple[str, int]] = Counter()
    state_counter: Counter[str] = Counter()

    for rec in records:
        pids.add(rec.pid)

        # Protocol
        proto = str(rec.protocol).upper()
        if "UDP" in proto:
            stats.udp_count += 1
        else:
            stats.tcp_count += 1

        # State
        state = rec.status or "NONE"
        state_counter[state] += 1

        # Remote IP/port
        if rec.remote_addr and rec.remote_addr not in ("0.0.0.0", "::", "*", ""):
            remote_ips.add(rec.remote_addr)
            ip_counter[rec.remote_addr] += 1

            # Internal vs external
            if _is_private(rec.remote_addr):
                stats.internal_count += 1
            else:
                stats.external_count += 1

        if rec.remote_port and rec.remote_port > 0:
            remote_ports.add(rec.remote_port)
            port_counter[rec.remote_port] += 1

        # Process
        proc_counter[(rec.process_name, rec.pid)] += 1

        # Listen vs established
        if state in ("LISTEN", "LISTENING"):
            stats.listen_count += 1
        elif state in ("ESTABLISHED", "ESTAB"):
            stats.established_count += 1

    stats.unique_remote_ips = len(remote_ips)
    stats.unique_remote_ports = len(remote_ports)
    stats.unique_processes = len(pids)
    stats.state_counts = dict(state_counter.most_common())

    stats.top_remote_ips = ip_counter.most_common(top_n)
    stats.top_remote_ports = port_counter.most_common(top_n)

    # Top processes: use profiles if available for richer info
    if profiles:
        sorted_procs = sorted(profiles, key=lambda p: p.total_connections, reverse=True)[:top_n]
        stats.top_processes = [(p.name, p.pid, p.total_connections) for p in sorted_procs]
    else:
        stats.top_processes = [(name, pid, cnt) for (name, pid), cnt in proc_counter.most_common(top_n)]

    return stats


def print_stats(stats: NetworkStats, *, colour: bool = True) -> None:
    """Print a formatted network statistics summary to stdout."""
    c, g, y, w, d, b, r = (_CYAN, _GREEN, _YELLOW, _WHITE, _DIM, _BOLD, _RESET) if colour else ("",) * 7

    sep = f"{d}{'-' * 60}{r}"

    print(f"\n{b}{c}+{'=' * 46}+{r}")
    print(f"{b}{c}|        NETWORK STATISTICS SUMMARY             |{r}")
    print(f"{b}{c}+{'=' * 46}+{r}\n")

    # Overview
    print(f"  {b}Connections:{r}  {w}{stats.total_connections}{r}")
    print(f"  {b}Unique IPs:{r}   {w}{stats.unique_remote_ips}{r}")
    print(f"  {b}Unique Ports:{r} {w}{stats.unique_remote_ports}{r}")
    print(f"  {b}Processes:{r}    {w}{stats.unique_processes}{r}")
    print()

    # Protocol breakdown
    print(f"  {b}Protocol Breakdown{r}")
    print(f"  {sep}")
    _bar(stats.tcp_count, stats.total_connections, "TCP", g, r, b)
    _bar(stats.udp_count, stats.total_connections, "UDP", y, r, b)
    print()

    # Traffic direction
    total_directional = stats.internal_count + stats.external_count
    if total_directional:
        print(f"  {b}Traffic Direction{r}")
        print(f"  {sep}")
        _bar(stats.internal_count, total_directional, "Internal", g, r, b)
        _bar(stats.external_count, total_directional, "External", y, r, b)
        print()

    # Connection states
    if stats.state_counts:
        print(f"  {b}Connection States{r}")
        print(f"  {sep}")
        for state, count in stats.state_counts.items():
            pct = (count / stats.total_connections * 100) if stats.total_connections else 0
            clr = g if state in ("ESTABLISHED", "ESTAB", "LISTEN", "LISTENING") else d
            print(f"    {clr}{state:<20}{r} {w}{count:>5}{r}  ({pct:.1f}%)")
        print()

    # Top Remote IPs
    if stats.top_remote_ips:
        print(f"  {b}Top Remote IPs{r}")
        print(f"  {sep}")
        for ip, count in stats.top_remote_ips:
            tag = f" {d}(local){r}" if _is_private(ip) else ""
            print(f"    {w}{ip:<40}{r} {c}{count:>4}{r} conn{tag}")
        print()

    # Top Processes
    if stats.top_processes:
        print(f"  {b}Top Processes (by connection count){r}")
        print(f"  {sep}")
        for name, pid, count in stats.top_processes:
            print(f"    {w}{name:<30}{r} {d}PID {pid:<8}{r} {c}{count:>4}{r} conn")
        print()

    # Top Remote Ports
    if stats.top_remote_ports:
        print(f"  {b}Top Remote Ports{r}")
        print(f"  {sep}")
        for port, count in stats.top_remote_ports:
            svc = _guess_service(port)
            svc_str = f" {d}({svc}){r}" if svc else ""
            print(f"    {w}{port:<8}{r} {c}{count:>4}{r} conn{svc_str}")
        print()


# ======================================================================
# Helpers
# ======================================================================

def _bar(value: int, total: int, label: str, colour: str, reset: str, bold: str) -> None:
    """Print a simple bar chart line."""
    pct = (value / total * 100) if total else 0
    bar_len = int(pct / 2.5)  # Max ~40 chars for 100%
    bar = "#" * bar_len
    print(f"    {bold}{label:<10}{reset} {colour}{bar}{reset} {value} ({pct:.1f}%)")


def _is_private(addr: str) -> bool:
    """Check if an IP address is in a private range."""
    try:
        from ipaddress import ip_address as _ip
        a = _ip(addr)
        return a.is_private or a.is_loopback or a.is_link_local
    except (ValueError, TypeError):
        return False


_WELL_KNOWN_PORTS = {
    21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1434: "MSSQL-B",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    9090: "Prometheus", 27017: "MongoDB",
}


def _guess_service(port: int) -> str:
    """Return a human-friendly service name for well-known ports."""
    return _WELL_KNOWN_PORTS.get(port, "")


def stats_to_dict(stats: NetworkStats) -> dict:
    """Serialise stats to a plain dict (for JSON/PDF)."""
    return {
        "total_connections": stats.total_connections,
        "unique_remote_ips": stats.unique_remote_ips,
        "unique_remote_ports": stats.unique_remote_ports,
        "unique_processes": stats.unique_processes,
        "tcp_count": stats.tcp_count,
        "udp_count": stats.udp_count,
        "state_counts": stats.state_counts,
        "listen_count": stats.listen_count,
        "established_count": stats.established_count,
        "external_count": stats.external_count,
        "internal_count": stats.internal_count,
        "top_remote_ips": stats.top_remote_ips,
        "top_processes": [(n, p, c) for n, p, c in stats.top_processes],
        "top_remote_ports": stats.top_remote_ports,
    }
