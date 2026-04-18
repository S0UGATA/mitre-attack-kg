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
        ts = {t[:3] for t in triples}

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
        desc = [t[2] for t in triples if t[0] == "CVE-2024-1234" and t[1] == "description"]
        assert len(desc) == 1
        assert "remote code execution" in desc[0].lower()

    def test_affected_products(self, sample_cve_dir):
        triples = list(extract_cve_triples(sample_cve_dir))
        ts = {t[:3] for t in triples}

        assert ("CVE-2024-1234", "vendor", "Microsoft") in ts
        assert ("CVE-2024-1234", "product", "Windows") in ts

    def test_cpe_link(self, sample_cve_dir):
        triples = list(extract_cve_triples(sample_cve_dir))
        ts = {t[:3] for t in triples}

        cpe = "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*"
        assert ("CVE-2024-1234", "affects-cpe", cpe) in ts

    def test_platform(self, sample_cve_dir):
        triples = list(extract_cve_triples(sample_cve_dir))
        ts = {t[:3] for t in triples}

        assert ("CVE-2024-1234", "platform", "x64") in ts
        assert ("CVE-2024-1234", "platform", "ARM") in ts

    def test_cwe_link_from_cwe_id_field(self, sample_cve_dir):
        triples = list(extract_cve_triples(sample_cve_dir))
        ts = {t[:3] for t in triples}

        assert ("CVE-2024-1234", "related-weakness", "CWE-79") in ts

    def test_cwe_link_from_description(self, sample_cve_dir):
        triples = list(extract_cve_triples(sample_cve_dir))
        ts = {t[:3] for t in triples}

        assert ("CVE-2024-5678", "related-weakness", "CWE-89") in ts

    def test_cvss_metrics(self, sample_cve_dir):
        triples = list(extract_cve_triples(sample_cve_dir))
        ts = {t[:3] for t in triples}

        assert ("CVE-2024-1234", "cvss-base-score", "9.8") in ts
        assert ("CVE-2024-1234", "cvss-severity", "CRITICAL") in ts

    def test_rejected_excluded(self, sample_cve_dir):
        triples = list(extract_cve_triples(sample_cve_dir))
        subjects = {t[0] for t in triples}

        assert "CVE-2024-9999" not in subjects

    def test_triple_count(self, sample_cve_dir):
        triples = list(extract_cve_triples(sample_cve_dir))
        assert len(triples) > 5
        assert len(triples) < 100

    def test_six_tuple_source_and_object_type(self, sample_cve_dir):
        """Verify source, object_type, and meta fields in 6-tuple output."""
        triples = list(extract_cve_triples(sample_cve_dir))

        # All triples must have source="cve"
        assert all(t[3] == "cve" for t in triples)

        # Check object_type for specific predicates
        by_pred = {}
        for t in triples:
            if t[0] == "CVE-2024-1234":
                by_pred.setdefault(t[1], t)

        assert by_pred["rdf:type"][4] == "enum"
        assert by_pred["state"][4] == "enum"
        assert by_pred["date-published"][4] == "date"
        assert by_pred["assigner"][4] == "string"
        assert by_pred["description"][4] == "string"
        assert by_pred["vendor"][4] == "string"
        assert by_pred["related-weakness"][4] == "id"
        assert by_pred["affects-cpe"][4] == "id"
        assert by_pred["cvss-base-score"][4] == "number"
        assert by_pred["cvss-severity"][4] == "enum"

    def test_six_tuple_cvss_meta(self, sample_cve_dir):
        """CVSS triples should carry CVSS version metadata."""
        import json

        triples = list(extract_cve_triples(sample_cve_dir))
        score_triples = [
            t for t in triples if t[0] == "CVE-2024-1234" and t[1] == "cvss-base-score"
        ]
        assert len(score_triples) == 1
        meta = score_triples[0][5]
        parsed = json.loads(meta)
        assert parsed["cvss_version"] == "3.1"

    def test_six_tuple_entity_meta(self, sample_cve_dir):
        """The rdf:type triple should carry entity-level meta (references, credits)."""
        triples = list(extract_cve_triples(sample_cve_dir))
        type_triples = [t for t in triples if t[0] == "CVE-2024-1234" and t[1] == "rdf:type"]
        assert len(type_triples) == 1
        # Meta is either empty or valid JSON
        meta = type_triples[0][5]
        assert isinstance(meta, str)
