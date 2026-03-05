"""Tests for netwatch.geoip"""

from unittest.mock import MagicMock, patch

import pytest

from netwatch.models import ConnectionRecord


class TestGeoIPEnricher:
    """Test GeoIPEnricher (mocked — no actual DB files needed)."""

    def test_import_and_instantiation_without_db(self):
        from netwatch.geoip import GeoIPEnricher
        g = GeoIPEnricher(db_path="/nonexistent/path")
        assert g.available is False

    def test_lookup_returns_none_when_unavailable(self):
        from netwatch.geoip import GeoIPEnricher
        g = GeoIPEnricher(db_path="/nonexistent/path")
        cc, cn, asn = g.lookup("8.8.8.8")
        assert cc is None
        assert cn is None
        assert asn is None

    def test_skips_private_ips(self):
        from netwatch.geoip import GeoIPEnricher
        g = GeoIPEnricher(db_path="/nonexistent/path")
        # Even if available were True, private IPs should be skipped
        for addr in ("127.0.0.1", "192.168.1.1", "10.0.0.1", "::1"):
            cc, cn, asn = g.lookup(addr)
            assert cc is None

    def test_skips_special_addrs(self):
        from netwatch.geoip import GeoIPEnricher
        g = GeoIPEnricher(db_path="/nonexistent/path")
        for addr in ("0.0.0.0", "::", "*", ""):
            cc, cn, asn = g.lookup(addr)
            assert cc is None

    def test_enrich_record_no_crash(self):
        from netwatch.geoip import GeoIPEnricher
        g = GeoIPEnricher(db_path="/nonexistent/path")
        rec = ConnectionRecord(
            pid=1, process_name="test.exe",
            local_addr="192.168.1.10", local_port=5000,
            remote_addr="8.8.8.8", remote_port=443,
            protocol="tcp", status="ESTABLISHED",
        )
        # Should not crash even when DB is unavailable
        g.enrich_record(rec)
        assert rec.geo_country is None


class TestGeoIPEnricherWithMockedDB:
    """Test GeoIP with a mocked geoip2 reader."""

    def test_lookup_with_mocked_reader(self):
        from netwatch.geoip import GeoIPEnricher

        enricher = GeoIPEnricher.__new__(GeoIPEnricher)
        enricher._available = True
        enricher._warned = False

        # Mock country reader
        country_resp = MagicMock()
        country_resp.country.iso_code = "US"
        country_resp.country.name = "United States"
        enricher._country_reader = MagicMock()
        enricher._country_reader.country.return_value = country_resp

        # Mock ASN reader
        asn_resp = MagicMock()
        asn_resp.autonomous_system_number = 15169
        asn_resp.autonomous_system_organization = "Google LLC"
        enricher._asn_reader = MagicMock()
        enricher._asn_reader.asn.return_value = asn_resp

        cc, cn, asn = enricher.lookup("8.8.8.8")
        assert cc == "US"
        assert cn == "United States"
        assert "Google" in asn

    def test_enrich_record_populates_fields(self):
        from netwatch.geoip import GeoIPEnricher

        enricher = GeoIPEnricher.__new__(GeoIPEnricher)
        enricher._available = True
        enricher._warned = False

        country_resp = MagicMock()
        country_resp.country.iso_code = "DE"
        country_resp.country.name = "Germany"
        enricher._country_reader = MagicMock()
        enricher._country_reader.country.return_value = country_resp

        asn_resp = MagicMock()
        asn_resp.autonomous_system_number = 24940
        asn_resp.autonomous_system_organization = "Hetzner"
        enricher._asn_reader = MagicMock()
        enricher._asn_reader.asn.return_value = asn_resp

        rec = ConnectionRecord(
            pid=1, process_name="test.exe",
            local_addr="192.168.1.10", local_port=5000,
            remote_addr="88.198.0.1", remote_port=443,
            protocol="tcp", status="ESTABLISHED",
        )
        enricher.enrich_record(rec)
        assert rec.geo_country == "DE"
        assert rec.geo_country_name == "Germany"
        assert "Hetzner" in rec.geo_asn
