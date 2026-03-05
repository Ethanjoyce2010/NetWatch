"""
GeoIP Enrichment — resolves remote IPs to country, country name, and ASN.

Uses MaxMind GeoLite2 databases (optional). Falls back gracefully if the
databases are not installed — all geo fields remain None.

Setup:
  1. Create a free MaxMind account at https://www.maxmind.com/en/geolite2/signup
  2. Download GeoLite2-Country.mmdb and GeoLite2-ASN.mmdb
  3. Place them in ~/.netwatch/ or specify the path via --geoip-db / config
"""

from __future__ import annotations

import logging
from ipaddress import ip_address
from pathlib import Path
from typing import Optional

logger = logging.getLogger("netwatch.geoip")

# Try to import geoip2 — graceful degradation if not installed
try:
    import geoip2.database  # type: ignore[import-unresolved]
    import geoip2.errors  # type: ignore[import-unresolved]
    _GEOIP2_AVAILABLE = True
except ImportError:
    geoip2 = None  # type: ignore[assignment]
    _GEOIP2_AVAILABLE = False
    logger.debug("geoip2 not installed — GeoIP enrichment disabled. pip install geoip2")

# RFC-1918 / loopback / link-local  (skip these for lookups)
_SKIP_ADDRS = {"0.0.0.0", "::", "*", "", "127.0.0.1", "::1"}


class GeoIPEnricher:
    """Wraps MaxMind GeoLite2 readers for country + ASN lookups."""

    def __init__(self, db_path: Optional[str] = None):
        self._country_reader = None
        self._asn_reader = None
        self._available = False
        self._warned = False

        if not _GEOIP2_AVAILABLE:
            return

        # Locate database files
        search_dirs = []
        if db_path:
            search_dirs.append(Path(db_path))
            # If a directory was given, look inside it
            p = Path(db_path)
            if p.is_dir():
                search_dirs.append(p)
            elif p.is_file():
                # Single file — try to figure out which DB it is
                search_dirs.append(p.parent)
        search_dirs.append(Path.home() / ".netwatch")
        search_dirs.append(Path(__file__).parent.parent)

        country_db = self._find_db(search_dirs, "GeoLite2-Country.mmdb")
        asn_db = self._find_db(search_dirs, "GeoLite2-ASN.mmdb")

        if country_db:
            try:
                self._country_reader = geoip2.database.Reader(str(country_db))  # type: ignore[union-attr]
                logger.info("GeoIP country DB loaded: %s", country_db)
            except Exception as exc:
                logger.warning("Failed to open GeoIP country DB: %s", exc)

        if asn_db:
            try:
                self._asn_reader = geoip2.database.Reader(str(asn_db))  # type: ignore[union-attr]
                logger.info("GeoIP ASN DB loaded: %s", asn_db)
            except Exception as exc:
                logger.warning("Failed to open GeoIP ASN DB: %s", exc)

        self._available = self._country_reader is not None or self._asn_reader is not None

        if not self._available and not self._warned:
            logger.info(
                "GeoIP databases not found. For IP geolocation, download GeoLite2 "
                "databases from https://www.maxmind.com/ and place in ~/.netwatch/"
            )
            self._warned = True

    @property
    def available(self) -> bool:
        return self._available

    def lookup(self, addr: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """Look up an IP address.

        Returns (country_code, country_name, asn_description).
        Any or all may be None.
        """
        if not self._available or not addr or addr in _SKIP_ADDRS:
            return None, None, None

        # Skip private / loopback IPs
        try:
            a = ip_address(addr)
            if a.is_private or a.is_loopback or a.is_link_local or a.is_multicast:
                return None, None, None
        except (ValueError, TypeError):
            return None, None, None

        country_code = None
        country_name = None
        asn_desc = None

        if self._country_reader:
            try:
                resp = self._country_reader.country(addr)
                country_code = resp.country.iso_code
                country_name = resp.country.name
            except (geoip2.errors.AddressNotFoundError, Exception):  # type: ignore[union-attr]
                pass

        if self._asn_reader:
            try:
                resp = self._asn_reader.asn(addr)
                asn_desc = f"AS{resp.autonomous_system_number} {resp.autonomous_system_organization}"
            except (geoip2.errors.AddressNotFoundError, Exception):  # type: ignore[union-attr]
                pass

        return country_code, country_name, asn_desc

    def enrich_record(self, record) -> None:
        """Enrich a ConnectionRecord in-place with geo fields."""
        if not self._available:
            return
        cc, cn, asn = self.lookup(record.remote_addr)
        record.geo_country = cc
        record.geo_country_name = cn
        record.geo_asn = asn

    def close(self) -> None:
        """Close database readers."""
        if self._country_reader:
            self._country_reader.close()
        if self._asn_reader:
            self._asn_reader.close()

    def __del__(self):
        self.close()

    @staticmethod
    def _find_db(search_dirs: list[Path], filename: str) -> Optional[Path]:
        """Search for a database file in the given directories."""
        for d in search_dirs:
            candidate = d / filename if d.is_dir() else d
            if candidate.exists() and candidate.name == filename:
                return candidate
            # Check if d itself is a directory containing the file
            if d.is_dir():
                candidate = d / filename
                if candidate.exists():
                    return candidate
        return None
