"""Tests for netwatch.whitelist"""

import json
from pathlib import Path

import pytest

from netwatch.whitelist import ProcessWhitelist


class TestProcessWhitelist:
    def test_empty_whitelist(self):
        wl = ProcessWhitelist(path="/nonexistent/path.json")
        assert wl.is_suppressed("any.exe", "Any Rule") is False
        assert wl.loaded is False

    def test_load_from_file(self, tmp_path):
        f = tmp_path / "whitelist.json"
        f.write_text(json.dumps({
            "svchost.exe": ["External Listener"],
            "steam.exe": ["External Listener", "Non-standard DNS Port"],
        }), encoding="utf-8")

        wl = ProcessWhitelist(path=str(f))
        assert wl.loaded is True
        assert wl.is_suppressed("svchost.exe", "External Listener") is True
        assert wl.is_suppressed("svchost.exe", "C2 Communication") is False
        assert wl.is_suppressed("steam.exe", "Non-standard DNS Port") is True

    def test_case_insensitive_process_name(self, tmp_path):
        f = tmp_path / "whitelist.json"
        f.write_text(json.dumps({
            "SvcHost.exe": ["External Listener"],
        }), encoding="utf-8")

        wl = ProcessWhitelist(path=str(f))
        assert wl.is_suppressed("svchost.exe", "External Listener") is True
        assert wl.is_suppressed("SVCHOST.EXE", "External Listener") is True

    def test_wildcard_suppresses_all(self, tmp_path):
        f = tmp_path / "whitelist.json"
        f.write_text(json.dumps({
            "safe.exe": ["*"],
        }), encoding="utf-8")

        wl = ProcessWhitelist(path=str(f))
        assert wl.is_suppressed("safe.exe", "Any Rule") is True
        assert wl.is_suppressed("safe.exe", "Another Rule") is True

    def test_summary(self, tmp_path):
        f = tmp_path / "whitelist.json"
        f.write_text(json.dumps({
            "a.exe": ["R1"],
            "b.exe": ["R2", "R3"],
        }), encoding="utf-8")

        wl = ProcessWhitelist(path=str(f))
        s = wl.summary()
        assert "2" in s  # 2 processes
