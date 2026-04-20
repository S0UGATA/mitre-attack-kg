"""Tests for convert_euvd.py — EUVD JSON -> SPO triples converter."""

import json

import pytest

from convert_euvd import extract_euvd_triples

SAMPLE_VULN = {
    "euvdId": "EUVD-2025-4893",
    "description": "Critical vulnerability in example product.",
    "datePublished": "2025-01-15",
    "baseScore": 9.8,
    "baseScoreVersion": "3.1",
    "baseScoreVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "epss": 0.42,
    "aliases": "CVE-2025-1234\nCVE-2025-1235",
    "productList": [
        {"vendor": "ExampleCorp", "product": "ExampleServer"},
        {"vendor": "ExampleCorp", "product": "ExampleClient"},
    ],
}

SAMPLE_VULN_MINIMAL = {
    "euvdId": "EUVD-2025-0001",
    "description": "Minor issue.",
    "datePublished": "2025-02-01",
}

SAMPLE_NO_ID = {
    "description": "No ID field.",
}


@pytest.fixture
def sample_file(tmp_path):
    data = [SAMPLE_VULN, SAMPLE_VULN_MINIMAL, SAMPLE_NO_ID]
    path = tmp_path / "euvd_dump.json"
    path.write_text(json.dumps(data))
    return str(path)


class TestEuvdTriples:
    def test_basic_properties(self, sample_file):
        triples = list(extract_euvd_triples(sample_file))
        ts = {t[:3] for t in triples}

        assert ("EUVD-2025-4893", "rdf:type", "EUVulnerability") in ts
        assert ("EUVD-2025-4893", "description", "Critical vulnerability in example product.") in ts
        assert ("EUVD-2025-4893", "date-published", "2025-01-15") in ts

    def test_cvss(self, sample_file):
        triples = list(extract_euvd_triples(sample_file))
        ts = {t[:3] for t in triples}

        assert ("EUVD-2025-4893", "cvss-base-score", "9.8") in ts
        cvss = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert ("EUVD-2025-4893", "cvss-vector", cvss) in ts

    def test_cvss_version_meta(self, sample_file):
        triples = list(extract_euvd_triples(sample_file))
        score_triples = [
            t for t in triples if t[0] == "EUVD-2025-4893" and t[1] == "cvss-base-score"
        ]
        assert len(score_triples) == 1
        meta = json.loads(score_triples[0][5])
        assert meta["cvss_version"] == "3.1"

    def test_epss(self, sample_file):
        triples = list(extract_euvd_triples(sample_file))
        ts = {t[:3] for t in triples}

        assert ("EUVD-2025-4893", "epss-score", "0.42") in ts

    def test_cve_links(self, sample_file):
        triples = list(extract_euvd_triples(sample_file))
        ts = {t[:3] for t in triples}

        assert ("EUVD-2025-4893", "related-cve", "CVE-2025-1234") in ts
        assert ("EUVD-2025-4893", "related-cve", "CVE-2025-1235") in ts

    def test_vendor_product(self, sample_file):
        triples = list(extract_euvd_triples(sample_file))
        ts = {t[:3] for t in triples}

        assert ("EUVD-2025-4893", "vendor", "ExampleCorp") in ts
        assert ("EUVD-2025-4893", "product", "ExampleServer") in ts
        assert ("EUVD-2025-4893", "product", "ExampleClient") in ts

    def test_minimal_vuln(self, sample_file):
        triples = list(extract_euvd_triples(sample_file))
        ts = {t[:3] for t in triples}

        assert ("EUVD-2025-0001", "rdf:type", "EUVulnerability") in ts
        assert ("EUVD-2025-0001", "date-published", "2025-02-01") in ts

    def test_no_id_skipped(self, sample_file):
        triples = list(extract_euvd_triples(sample_file))
        subjects = {t[0] for t in triples}
        assert "" not in subjects

    def test_triple_count(self, sample_file):
        triples = list(extract_euvd_triples(sample_file))
        assert len(triples) > 5
        assert len(triples) < 50
