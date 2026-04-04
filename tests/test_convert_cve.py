"""Tests for convert_cve.py — CVE JSON 5.x → SPO triples converter."""

import json

import pytest

from convert_cve import _extract_single_cve, _parse_cwe_id, extract_cve_triples

SAMPLE_CVE_PUBLISHED = {
    "cveMetadata": {
        "cveId": "CVE-2024-1234",
        "state": "PUBLISHED",
        "datePublished": "2024-01-15T00:00:00.000Z",
        "dateUpdated": "2024-02-01T00:00:00.000Z",
        "assignerShortName": "microsoft",
    },
    "containers": {
        "cna": {
            "descriptions": [
                {"lang": "en", "value": "A remote code execution vulnerability."},
                {"lang": "es", "value": "Vulnerabilidad de ejecucion remota."},
            ],
            "affected": [
                {
                    "vendor": "Microsoft",
                    "product": "Windows",
                    "cpes": ["cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*"],
                    "platforms": ["x64", "ARM"],
                },
            ],
            "problemTypes": [
                {
                    "descriptions": [
                        {"cweId": "CWE-79", "description": "CWE-79 Cross-site Scripting"},
                    ],
                },
            ],
            "metrics": [
                {
                    "cvssV3_1": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                    },
                },
            ],
        },
    },
}

SAMPLE_CVE_REJECTED = {
    "cveMetadata": {
        "cveId": "CVE-2024-9999",
        "state": "REJECTED",
    },
    "containers": {},
}

SAMPLE_CVE_MINIMAL = {
    "cveMetadata": {
        "cveId": "CVE-2024-5678",
        "state": "PUBLISHED",
    },
    "containers": {
        "cna": {
            "descriptions": [],
            "problemTypes": [
                {
                    "descriptions": [
                        {"description": "CWE-89 SQL Injection"},
                    ],
                },
            ],
        },
    },
}


@pytest.fixture
def sample_cve_dir(tmp_path):
    d = tmp_path / "cves" / "2024"
    d.mkdir(parents=True)
    (d / "CVE-2024-1234.json").write_text(json.dumps(SAMPLE_CVE_PUBLISHED))
    (d / "CVE-2024-9999.json").write_text(json.dumps(SAMPLE_CVE_REJECTED))
    (d / "CVE-2024-5678.json").write_text(json.dumps(SAMPLE_CVE_MINIMAL))
    return str(tmp_path)


class TestParseCweId:
    def test_valid_cwe(self):
        assert _parse_cwe_id("CWE-79 Cross-site Scripting") == "CWE-79"

    def test_cwe_only(self):
        assert _parse_cwe_id("CWE-89") == "CWE-89"

    def test_no_cwe(self):
        assert _parse_cwe_id("Some other description") is None

    def test_empty(self):
        assert _parse_cwe_id("") is None


class TestSingleCve:
    def test_published_cve(self):
        triples = _extract_single_cve(SAMPLE_CVE_PUBLISHED)
        ts = set(triples)

        assert ("CVE-2024-1234", "rdf:type", "Vulnerability") in ts
        assert ("CVE-2024-1234", "state", "PUBLISHED") in ts
        assert ("CVE-2024-1234", "date-published", "2024-01-15T00:00:00.000Z") in ts
        assert ("CVE-2024-1234", "date-updated", "2024-02-01T00:00:00.000Z") in ts
        assert ("CVE-2024-1234", "assigner", "microsoft") in ts

    def test_rejected_skipped(self):
        triples = _extract_single_cve(SAMPLE_CVE_REJECTED)
        assert triples == []

    def test_no_cve_id(self):
        triples = _extract_single_cve({"cveMetadata": {}})
        assert triples == []


class TestCveTriples:
    def test_description_english_only(self, sample_cve_dir):
        triples = list(extract_cve_triples(sample_cve_dir))
        desc = [o for s, p, o in triples if s == "CVE-2024-1234" and p == "description"]
        assert len(desc) == 1
        assert "remote code execution" in desc[0].lower()

    def test_affected_products(self, sample_cve_dir):
        triples = list(extract_cve_triples(sample_cve_dir))
        ts = set(triples)

        assert ("CVE-2024-1234", "vendor", "Microsoft") in ts
        assert ("CVE-2024-1234", "product", "Windows") in ts

    def test_cpe_link(self, sample_cve_dir):
        triples = list(extract_cve_triples(sample_cve_dir))
        ts = set(triples)

        cpe = "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*"
        assert ("CVE-2024-1234", "affects-cpe", cpe) in ts

    def test_platform(self, sample_cve_dir):
        triples = list(extract_cve_triples(sample_cve_dir))
        ts = set(triples)

        assert ("CVE-2024-1234", "platform", "x64") in ts
        assert ("CVE-2024-1234", "platform", "ARM") in ts

    def test_cwe_link_from_cwe_id_field(self, sample_cve_dir):
        triples = list(extract_cve_triples(sample_cve_dir))
        ts = set(triples)

        assert ("CVE-2024-1234", "related-weakness", "CWE-79") in ts

    def test_cwe_link_from_description(self, sample_cve_dir):
        triples = list(extract_cve_triples(sample_cve_dir))
        ts = set(triples)

        assert ("CVE-2024-5678", "related-weakness", "CWE-89") in ts

    def test_cvss_metrics(self, sample_cve_dir):
        triples = list(extract_cve_triples(sample_cve_dir))
        ts = set(triples)

        assert ("CVE-2024-1234", "cvss-base-score", "9.8") in ts
        assert ("CVE-2024-1234", "cvss-severity", "CRITICAL") in ts

    def test_rejected_excluded(self, sample_cve_dir):
        triples = list(extract_cve_triples(sample_cve_dir))
        subjects = {s for s, _, _ in triples}

        assert "CVE-2024-9999" not in subjects

    def test_triple_count(self, sample_cve_dir):
        triples = list(extract_cve_triples(sample_cve_dir))
        assert len(triples) > 5
        assert len(triples) < 100
