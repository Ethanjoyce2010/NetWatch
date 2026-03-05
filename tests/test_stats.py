"""Tests for netwatch.stats"""

import time

import pytest

from netwatch.models import Alert, ConnectionRecord, ProcessProfile, Severity
from netwatch.stats import NetworkStats, compute_stats, stats_to_dict


def _make_record(
    pid: int = 100,
    process_name: str = "test.exe",
    local_addr: str = "192.168.1.10",
    local_port: int = 5000,
    remote_addr: str = "93.184.216.34",
    remote_port: int = 443,
    protocol: str = "tcp",
    status: str = "ESTABLISHED",
    timestamp: float | None = None,
) -> ConnectionRecord:
    return ConnectionRecord(
        pid=pid,
        process_name=process_name,
        local_addr=local_addr,
        local_port=local_port,
        remote_addr=remote_addr,
        remote_port=remote_port,
        protocol=protocol,
        status=status,
        timestamp=timestamp or time.time(),
    )


def _make_profile(pid=1, name="test.exe", connections=5):
    p = ProcessProfile(pid=pid, name=name, total_connections=connections)
    return p


class TestComputeStats:
    def test_empty_input(self):
        stats = compute_stats([], [])
        assert stats.total_connections == 0
        assert stats.unique_remote_ips == 0

    def test_counts(self):
        recs = [
            _make_record(remote_addr="1.2.3.4", remote_port=80, protocol="tcp", status="ESTABLISHED"),
            _make_record(remote_addr="5.6.7.8", remote_port=443, protocol="tcp", status="ESTABLISHED"),
            _make_record(remote_addr="1.2.3.4", remote_port=53, protocol="udp", status="NONE"),
        ]
        stats = compute_stats(recs, [])
        assert stats.total_connections == 3
        assert stats.unique_remote_ips == 2
        assert stats.tcp_count == 2
        assert stats.udp_count == 1

    def test_top_remote_ips(self):
        recs = [_make_record(remote_addr="1.1.1.1") for _ in range(5)]
        recs += [_make_record(remote_addr="8.8.8.8") for _ in range(3)]
        stats = compute_stats(recs, [], top_n=2)
        assert len(stats.top_remote_ips) <= 2
        assert stats.top_remote_ips[0][0] == "1.1.1.1"  # most frequent
        assert stats.top_remote_ips[0][1] == 5


class TestStatsToDict:
    def test_round_trip(self):
        stats = NetworkStats(
            total_connections=10,
            unique_remote_ips=5,
            tcp_count=8,
            udp_count=2,
        )
        d = stats_to_dict(stats)
        assert isinstance(d, dict)
        assert d["total_connections"] == 10
        assert d["unique_remote_ips"] == 5
        assert d["tcp_count"] == 8
