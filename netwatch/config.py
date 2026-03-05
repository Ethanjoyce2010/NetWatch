"""
Configuration loader — reads netwatch.toml and merges with CLI args.

Priority: CLI flags > environment variables > config file > hardcoded defaults.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("netwatch.config")

_DEFAULT_FILE = "netwatch.toml"


# ======================================================================
# Config data-classes
# ======================================================================

@dataclass
class MonitorConfig:
    poll_interval: float = 2.0
    duration: int = 0


@dataclass
class DetectorConfig:
    connection_rate_threshold: int = 80
    rate_window_seconds: float = 60.0
    min_unique_ips_for_scan_alert: int = 30
    port_scan_unique_ports: int = 20
    beacon_min_intervals: int = 5
    beacon_jitter_tolerance: float = 0.20
    min_risk_score: int = 10


@dataclass
class FeedsConfig:
    cache_max_age_seconds: int = 3600
    api_key: str = ""


@dataclass
class NotificationsConfig:
    discord_webhook: str = ""
    slack_webhook: str = ""
    email_to: str = ""
    email_smtp: str = ""
    email_port: int = 587
    email_user: str = ""
    email_password: str = ""
    email_from: str = "netwatch@localhost"
    min_severity: str = "HIGH"
    cooldown_seconds: int = 300


@dataclass
class GeoIPConfig:
    db_path: str = ""
    license_key: str = ""


@dataclass
class ReportingConfig:
    pdf_output: str = ""
    html_output: str = ""
    csv_output: str = ""


@dataclass
class NetWatchConfig:
    """Top-level configuration container."""

    monitor: MonitorConfig = field(default_factory=MonitorConfig)
    detector: DetectorConfig = field(default_factory=DetectorConfig)
    feeds: FeedsConfig = field(default_factory=FeedsConfig)
    notifications: NotificationsConfig = field(default_factory=NotificationsConfig)
    geoip: GeoIPConfig = field(default_factory=GeoIPConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)


# ======================================================================
# TOML loader
# ======================================================================

def _load_toml(path: Path) -> dict[str, Any]:
    """Load a TOML file, using tomllib (3.11+) or tomli as fallback."""
    try:
        import tomllib  # Python 3.11+
    except ModuleNotFoundError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ModuleNotFoundError:
            logger.warning(
                "TOML support requires Python 3.11+ or 'tomli' package. "
                "Install with: pip install tomli"
            )
            return {}

    text = path.read_bytes()
    return tomllib.loads(text.decode("utf-8"))


def _apply_section(target, data: dict[str, Any]) -> None:
    """Overlay a dict of values onto a dataclass instance."""
    for key, value in data.items():
        if hasattr(target, key):
            expected_type = type(getattr(target, key))
            try:
                setattr(target, key, expected_type(value))
            except (TypeError, ValueError) as exc:
                logger.warning("Config key '%s': %s", key, exc)
        else:
            logger.debug("Unknown config key ignored: %s", key)


# ======================================================================
# Environment variable overrides
# ======================================================================

_ENV_MAP: dict[str, tuple[str, str]] = {
    # env var → (section_attr, field_name)
    "NETWATCH_POLL_INTERVAL":          ("monitor", "poll_interval"),
    "NETWATCH_DURATION":               ("monitor", "duration"),
    "NETWATCH_RATE_THRESHOLD":         ("detector", "connection_rate_threshold"),
    "NETWATCH_MIN_RISK":               ("detector", "min_risk_score"),
    "NETWATCH_FEED_CACHE_AGE":         ("feeds", "cache_max_age_seconds"),
    "ABUSE_CH_API_KEY":                ("feeds", "api_key"),
    "NETWATCH_DISCORD_WEBHOOK":        ("notifications", "discord_webhook"),
    "NETWATCH_SLACK_WEBHOOK":          ("notifications", "slack_webhook"),
    "NETWATCH_EMAIL_TO":               ("notifications", "email_to"),
    "NETWATCH_EMAIL_SMTP":             ("notifications", "email_smtp"),
    "NETWATCH_NOTIFY_MIN_SEVERITY":    ("notifications", "min_severity"),
    "NETWATCH_NOTIFY_COOLDOWN":        ("notifications", "cooldown_seconds"),
    "NETWATCH_GEOIP_DB":              ("geoip", "db_path"),
    "MAXMIND_LICENSE_KEY":             ("geoip", "license_key"),
}


def _apply_env(cfg: NetWatchConfig) -> None:
    """Override config values from environment variables."""
    for env_var, (section_attr, field_name) in _ENV_MAP.items():
        value = os.environ.get(env_var)
        if value is not None:
            section = getattr(cfg, section_attr)
            expected_type = type(getattr(section, field_name))
            try:
                setattr(section, field_name, expected_type(value))
                logger.debug("Config override from env %s: %s.%s = %s",
                             env_var, section_attr, field_name, value)
            except (TypeError, ValueError) as exc:
                logger.warning("Env var %s: %s", env_var, exc)


# ======================================================================
# Auto-discovery
# ======================================================================

def _find_config_file(explicit_path: Optional[str] = None) -> Optional[Path]:
    """Locate netwatch.toml — explicit path, CWD, or project root."""
    if explicit_path:
        p = Path(explicit_path)
        if p.is_file():
            return p
        logger.warning("Config file not found: %s", explicit_path)
        return None

    candidates = [
        Path.cwd() / _DEFAULT_FILE,
        Path(__file__).parent.parent / _DEFAULT_FILE,
    ]
    for c in candidates:
        if c.is_file():
            return c
    return None


# ======================================================================
# Public API
# ======================================================================

def load_config(explicit_path: Optional[str] = None) -> NetWatchConfig:
    """Load configuration with priority: file → env → defaults.

    CLI args should be merged on top by the caller.
    """
    cfg = NetWatchConfig()

    # 1. Load from TOML file
    path = _find_config_file(explicit_path)
    if path:
        logger.info("Loading config from %s", path)
        data = _load_toml(path)
        for section_name in ("monitor", "detector", "feeds", "notifications", "geoip", "reporting"):
            if section_name in data:
                _apply_section(getattr(cfg, section_name), data[section_name])
    else:
        logger.debug("No config file found — using defaults.")

    # 2. Override from environment variables
    _apply_env(cfg)

    return cfg
