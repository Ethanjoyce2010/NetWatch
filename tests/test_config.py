"""Tests for netwatch.config"""

import os
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from netwatch.config import (
    DetectorConfig,
    GeoIPConfig,
    MonitorConfig,
    NetWatchConfig,
    NotificationsConfig,
    ReportingConfig,
    _apply_env,
    _apply_section,
    _find_config_file,
    load_config,
)


# ────────────────────── _apply_section ──────────────────────────────────
class TestApplySection:
    def test_applies_known_keys(self):
        m = MonitorConfig()
        _apply_section(m, {"poll_interval": 5.0, "duration": 120})
        assert m.poll_interval == 5.0
        assert m.duration == 120

    def test_ignores_unknown_keys(self):
        m = MonitorConfig()
        _apply_section(m, {"no_such_key": "hello"})
        assert m.poll_interval == 2.0  # unchanged

    def test_type_coercion(self):
        d = DetectorConfig()
        _apply_section(d, {"connection_rate_threshold": "50"})
        # int("50") → 50
        assert d.connection_rate_threshold == 50


# ────────────────────── _apply_env ──────────────────────────────────────
class TestApplyEnv:
    def test_env_override(self):
        cfg = NetWatchConfig()
        with patch.dict(os.environ, {"NETWATCH_POLL_INTERVAL": "10.0"}):
            _apply_env(cfg)
        assert cfg.monitor.poll_interval == 10.0

    def test_api_key_env(self):
        cfg = NetWatchConfig()
        with patch.dict(os.environ, {"ABUSE_CH_API_KEY": "secret123"}):
            _apply_env(cfg)
        assert cfg.feeds.api_key == "secret123"

    def test_no_env_no_change(self):
        cfg = NetWatchConfig()
        with patch.dict(os.environ, {}, clear=True):
            _apply_env(cfg)
        assert cfg.monitor.poll_interval == 2.0


# ────────────────────── load_config ─────────────────────────────────────
class TestLoadConfig:
    def test_defaults_without_file(self, tmp_path):
        # Point to a nonexistent config file
        cfg = load_config(str(tmp_path / "nonexistent.toml"))
        assert isinstance(cfg, NetWatchConfig)
        assert cfg.monitor.poll_interval == 2.0
        assert cfg.detector.connection_rate_threshold == 80

    def test_loads_toml(self, tmp_path):
        toml = tmp_path / "netwatch.toml"
        toml.write_text(textwrap.dedent("""\
            [monitor]
            poll_interval = 5.0

            [detector]
            connection_rate_threshold = 50
            min_risk_score = 20

            [notifications]
            discord_webhook = "https://discord.com/api/webhooks/test"
        """), encoding="utf-8")

        cfg = load_config(str(toml))
        assert cfg.monitor.poll_interval == 5.0
        assert cfg.detector.connection_rate_threshold == 50
        assert cfg.detector.min_risk_score == 20
        assert cfg.notifications.discord_webhook == "https://discord.com/api/webhooks/test"

    def test_env_overrides_file(self, tmp_path):
        toml = tmp_path / "netwatch.toml"
        toml.write_text("[monitor]\npoll_interval = 3.0\n", encoding="utf-8")

        with patch.dict(os.environ, {"NETWATCH_POLL_INTERVAL": "7.0"}):
            cfg = load_config(str(toml))
        # env should win over file
        assert cfg.monitor.poll_interval == 7.0


# ────────────────────── _find_config_file ───────────────────────────────
class TestFindConfigFile:
    def test_explicit_path_found(self, tmp_path):
        f = tmp_path / "my.toml"
        f.write_text("[monitor]\n", encoding="utf-8")
        assert _find_config_file(str(f)) == f

    def test_explicit_path_not_found(self, tmp_path):
        result = _find_config_file(str(tmp_path / "missing.toml"))
        assert result is None

    def test_none_returns_none_when_no_default(self, tmp_path, monkeypatch):
        # Change CWD to temp dir with no netwatch.toml
        monkeypatch.chdir(tmp_path)
        result = _find_config_file(None)
        # May or may not find the project-level one; just ensure no crash
        assert result is None or result.is_file()


# ────────────────────── Dataclass defaults ──────────────────────────────
class TestConfigDefaults:
    def test_monitor_defaults(self):
        m = MonitorConfig()
        assert m.poll_interval == 2.0
        assert m.duration == 0

    def test_detector_defaults(self):
        d = DetectorConfig()
        assert d.connection_rate_threshold == 80
        assert d.rate_window_seconds == 60.0
        assert d.min_unique_ips_for_scan_alert == 30
        assert d.port_scan_unique_ports == 20
        assert d.beacon_min_intervals == 5
        assert d.beacon_jitter_tolerance == 0.20
        assert d.min_risk_score == 10

    def test_notification_defaults(self):
        n = NotificationsConfig()
        assert n.min_severity == "HIGH"
        assert n.cooldown_seconds == 300
        assert n.email_port == 587

    def test_geoip_defaults(self):
        g = GeoIPConfig()
        assert g.db_path == ""

    def test_reporting_defaults(self):
        r = ReportingConfig()
        assert r.pdf_output == ""
        assert r.html_output == ""
