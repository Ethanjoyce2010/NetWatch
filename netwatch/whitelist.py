"""
Process Whitelist — suppresses alerts for known-good processes.

Loads a whitelist.json from the project directory (or a user-specified
path) that maps process names to suppressed rule names. Whitelisted
alerts are silently dropped so the report only shows genuine findings.

Example whitelist.json:
{
    "svchost.exe": ["External Listener"],
    "mDNSResponder.exe": ["External Listener", "Non-standard DNS Port"],
    "steam.exe": ["External Listener"],
    "AnyDesk.exe": ["External Listener"],
    "vmware-authd.exe": ["External Listener"]
}
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("netwatch.whitelist")

_DEFAULT_FILE = "whitelist.json"


class ProcessWhitelist:
    """Manages a per-process alert suppression list."""

    def __init__(self, path: Optional[str] = None):
        self._rules: dict[str, set[str]] = {}
        self._path: Optional[Path] = None
        self._load(path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_suppressed(self, process_name: str, rule_name: str) -> bool:
        """Return True if this process+rule combination should be suppressed."""
        key = process_name.lower()
        if key in self._rules:
            suppressed = self._rules[key]
            if "*" in suppressed or rule_name in suppressed:
                return True
        return False

    @property
    def loaded(self) -> bool:
        return bool(self._rules)

    @property
    def entry_count(self) -> int:
        return len(self._rules)

    @property
    def file_path(self) -> Optional[str]:
        return str(self._path) if self._path else None

    def summary(self) -> str:
        """Human-readable summary of loaded whitelist."""
        if not self._rules:
            return "No whitelist loaded."
        total_rules = sum(len(v) for v in self._rules.values())
        return (
            f"Whitelist: {len(self._rules)} process(es), "
            f"{total_rules} suppression rule(s) from {self._path}"
        )

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _load(self, path: Optional[str]) -> None:
        """Try to load whitelist from the given path or auto-discover."""
        candidates: list[Path] = []
        if path:
            candidates.append(Path(path))
        else:
            # Auto-discover in the working directory and script directory
            candidates.append(Path.cwd() / _DEFAULT_FILE)
            candidates.append(Path(__file__).parent.parent / _DEFAULT_FILE)

        for candidate in candidates:
            if candidate.is_file():
                try:
                    data = json.loads(candidate.read_text(encoding="utf-8"))
                    self._parse(data)
                    self._path = candidate
                    logger.info("Loaded whitelist: %s (%d entries)", candidate, len(self._rules))
                    return
                except (json.JSONDecodeError, ValueError) as exc:
                    logger.warning("Failed to parse whitelist %s: %s", candidate, exc)
                    return

        logger.debug("No whitelist file found (checked %s)", [str(c) for c in candidates])

    def _parse(self, data: dict) -> None:
        """Parse the raw JSON into normalised lookup table."""
        if not isinstance(data, dict):
            raise ValueError("Whitelist must be a JSON object {process_name: [rules]}")

        for proc, rules in data.items():
            key = proc.strip().lower()
            if isinstance(rules, list):
                self._rules[key] = set(rules)
            elif isinstance(rules, str):
                self._rules[key] = {rules}
            elif rules == "*" or rules is True:
                self._rules[key] = {"*"}
            else:
                logger.warning("Ignoring invalid whitelist entry for '%s'", proc)
