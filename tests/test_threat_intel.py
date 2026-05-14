"""Tests for netwatch.threat_intel"""

from netwatch.threat_intel import MALWARE_FAMILIES, ThreatIntelManager


class TestMalwareFamilyInfo:
    def test_database_contains_expanded_family_descriptions(self):
        expected = {
            "bazarloader",
            "gootloader",
            "zloader",
            "ursnif",
            "danabot",
            "lockbit",
            "alphv",
            "xmrig",
        }

        assert expected.issubset(MALWARE_FAMILIES)
        assert len(MALWARE_FAMILIES) >= 50

    def test_lookup_is_case_insensitive(self, tmp_path):
        ti = ThreatIntelManager(cache_dir=tmp_path)

        info = ti.get_malware_info("BAZARLOADER")

        assert info is not None
        assert "BazarLoader" in info

    def test_lookup_accepts_common_alias_formats(self, tmp_path):
        ti = ThreatIntelManager(cache_dir=tmp_path)

        assert ti.get_malware_info("CobaltStrike") == MALWARE_FAMILIES["cobalt_strike"]
        assert ti.get_malware_info("RedLine Stealer") == MALWARE_FAMILIES["redline"]
        assert ti.get_malware_info("Black Cat") == MALWARE_FAMILIES["alphv"]

    def test_unknown_family_returns_none(self, tmp_path):
        ti = ThreatIntelManager(cache_dir=tmp_path)

        assert ti.get_malware_info("definitely-not-real") is None


class TestExternalThreatIntelProviders:
    def test_ingest_otx_pulses_adds_indicators(self, tmp_path):
        ti = ThreatIntelManager(cache_dir=tmp_path)
        data = {
            "results": [{
                "name": "Test Cobalt Strike pulse",
                "tags": ["cobalt strike"],
                "indicators": [
                    {"type": "IPv4", "indicator": "203.0.113.10"},
                    {"type": "domain", "indicator": "evil.example"},
                    {"type": "URL", "indicator": "https://evil.example/a"},
                    {"type": "FileHash-SHA256", "indicator": "a" * 64},
                ],
            }]
        }

        count = ti.ingest_otx_pulses(data)

        assert count == 4
        assert "203.0.113.10" in ti.c2_ips
        assert "evil.example" in ti.malicious_domains
        assert "https://evil.example/a" in ti.malicious_urls
        assert ti.malicious_hashes["a" * 64] == "cobalt strike"

    def test_otx_lookup_returns_match_from_pulse_info(self, tmp_path, monkeypatch):
        ti = ThreatIntelManager(cache_dir=tmp_path)
        payload = {
            "pulse_info": {
                "count": 2,
                "pulses": [
                    {
                        "name": "Cobalt Strike infrastructure",
                        "tags": ["cobalt strike"],
                        "created": "2026-01-02T00:00:00",
                    }
                ],
            }
        }
        monkeypatch.setattr(ti, "_request_json", lambda url, headers=None: payload)

        match = ti.lookup_otx_indicator("203.0.113.10", api_key="key")

        assert match is not None
        assert match.source == "AlienVault OTX"
        assert match.indicator_type == "ip"
        assert match.confidence == "medium"
        assert match.description is not None
        assert "2 pulse" in match.description

    def test_virustotal_lookup_returns_malicious_reputation(self, tmp_path, monkeypatch):
        ti = ThreatIntelManager(cache_dir=tmp_path)
        payload = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 4, "suspicious": 1},
                    "popular_threat_classification": {
                        "suggested_threat_label": "redline",
                    },
                    "first_submission_date": 1_700_000_000,
                }
            }
        }
        monkeypatch.setattr(ti, "_request_json", lambda url, headers=None: payload)

        match = ti.lookup_virustotal_indicator("b" * 64, api_key="key")

        assert match is not None
        assert match.source == "VirusTotal"
        assert match.indicator_type == "hash"
        assert match.confidence == "high"
        assert match.malware_family == "redline"

    def test_provider_lookups_without_keys_return_none(self, tmp_path):
        ti = ThreatIntelManager(cache_dir=tmp_path)

        assert ti.lookup_otx_indicator("203.0.113.10") is None
        assert ti.lookup_virustotal_indicator("203.0.113.10") is None
