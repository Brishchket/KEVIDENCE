"""
test_parser.py — Tests for the CVE parser, including malformed samples.
"""
import json
import pytest
from app.ingestion.parser import parse_cve, _extract_cvss, _extract_cwe_ids, _extract_patch_references


class TestParseCVE:
    def test_full_cve(self):
        """Parse a complete NVD CVE record."""
        raw = {
            "id": "CVE-2024-1234",
            "descriptions": [{"lang": "en", "value": "Test vuln"}],
            "metrics": {
                "cvssMetricV31": [{
                    "type": "Primary",
                    "cvssData": {
                        "baseScore": 9.8,
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "baseSeverity": "CRITICAL",
                        "attackVector": "NETWORK",
                    }
                }]
            },
            "weaknesses": [{"description": [{"value": "CWE-787", "lang": "en"}]}],
            "configurations": [{
                "nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"}]}]
            }],
            "references": [
                {"url": "https://example.com/advisory", "tags": ["Vendor Advisory"]},
                {"url": "https://example.com/patch", "tags": ["Patch"]},
                {"url": "https://example.com/info", "tags": []},
            ],
            "published": "2024-01-01T00:00:00",
            "lastModified": "2024-01-02T00:00:00",
        }
        result = parse_cve(raw)
        assert result is not None
        assert result["cve_id"] == "CVE-2024-1234"
        assert result["cvss_base_score"] == 9.8
        assert result["attack_vector"] == "NETWORK"
        assert "CWE-787" in json.loads(result["cwe_ids"])
        assert len(json.loads(result["patch_references"])) == 2
        assert len(json.loads(result["reference_urls"])) == 3

    def test_missing_id(self):
        """CVE with no ID returns None."""
        assert parse_cve({}) is None

    def test_missing_metrics(self):
        """CVE with no CVSS data parses with None scores."""
        raw = {"id": "CVE-2024-0000", "descriptions": [{"lang": "en", "value": "No metrics"}]}
        result = parse_cve(raw)
        assert result is not None
        assert result["cvss_base_score"] is None
        assert result["attack_vector"] is None

    def test_missing_description(self):
        """CVE with no description still parses."""
        raw = {"id": "CVE-2024-NODESC", "descriptions": []}
        result = parse_cve(raw)
        assert result is not None
        assert result["description"] == ""

    def test_non_english_description_fallback(self):
        """Falls back to first description if no English."""
        raw = {
            "id": "CVE-2024-LANG",
            "descriptions": [{"lang": "es", "value": "Vulnerabilidad de prueba"}],
        }
        result = parse_cve(raw)
        assert result["description"] == "Vulnerabilidad de prueba"

    def test_malformed_cpe(self):
        """Malformed CPE strings don't crash."""
        raw = {
            "id": "CVE-2024-BADCPE",
            "descriptions": [{"lang": "en", "value": "Bad CPE"}],
            "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "invalid"}]}]}],
        }
        result = parse_cve(raw)
        assert result is not None
        assert json.loads(result["vendors"]) == []

    def test_empty_weaknesses(self):
        """Empty weaknesses list produces empty CWE list."""
        raw = {
            "id": "CVE-2024-NOCWE",
            "descriptions": [{"lang": "en", "value": "No CWE"}],
            "weaknesses": [],
        }
        result = parse_cve(raw)
        assert json.loads(result["cwe_ids"]) == []

    def test_cvss_v2_fallback(self):
        """Falls back to CVSS v2 when v3 is missing."""
        raw = {
            "id": "CVE-2024-V2",
            "descriptions": [{"lang": "en", "value": "v2 only"}],
            "metrics": {
                "cvssMetricV2": [{
                    "type": "Primary",
                    "baseSeverity": "HIGH",
                    "cvssData": {"baseScore": 7.5, "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
                }]
            },
        }
        result = parse_cve(raw)
        assert result["cvss_base_score"] == 7.5

    def test_epss_data_injected(self):
        """EPSS data is correctly injected into the parsed record."""
        raw = {"id": "CVE-2024-EPSS", "descriptions": [{"lang": "en", "value": "EPSS test"}]}
        epss = {"probability": 0.85, "percentile": 0.97}
        result = parse_cve(raw, epss_data=epss)
        assert result["epss_score"] == 0.85
        assert result["epss_percentile"] == 0.97

    def test_kev_record_sets_flag(self):
        """KEV record sets in_kev to True."""
        raw = {"id": "CVE-2024-KEV", "descriptions": [{"lang": "en", "value": "KEV test"}]}
        kev = {"date_added": "2024-01-01", "required_action": "Patch"}
        result = parse_cve(raw, kev_record=kev)
        assert result["in_kev"] is True


class TestExtractPatchReferences:
    def test_patch_tagged(self):
        refs = [
            {"url": "https://a.com", "tags": ["Patch"]},
            {"url": "https://b.com", "tags": ["Third Party Advisory"]},
        ]
        all_urls, patch_urls = _extract_patch_references(refs)
        assert len(all_urls) == 2
        assert len(patch_urls) == 1
        assert patch_urls[0] == "https://a.com"

    def test_vendor_advisory_tagged(self):
        refs = [{"url": "https://vendor.com", "tags": ["Vendor Advisory"]}]
        _, patch_urls = _extract_patch_references(refs)
        assert len(patch_urls) == 1
