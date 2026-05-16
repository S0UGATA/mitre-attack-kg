"""Tests for convert_osv.py — OSV JSON -> SPO triples converter."""

import json

import pytest

from convert_osv import extract_osv_triples

SAMPLE_PYSEC = {
    "id": "PYSEC-2024-1234",
    "summary": "Arbitrary code execution in example-package.",
    "published": "2024-03-15T00:00:00Z",
    "modified": "2024-03-20T00:00:00Z",
    "aliases": ["CVE-2024-5678"],
    "database_specific": {
        "cwe_ids": ["CWE-94"],
    },
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "example-package"},
        },
    ],
    "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    ],
}

SAMPLE_GHSA = {
    "id": "GHSA-abcd-efgh-ijkl",
    "summary": "XSS in react-widget.",
    "published": "2024-04-01T00:00:00Z",
    "modified": "2024-04-05T00:00:00Z",
    "aliases": ["CVE-2024-9999"],
    "database_specific": {
        "cwe_ids": ["CWE-79"],
    },
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "react-widget"},
        },
    ],
}

SAMPLE_MULTI_AFFECTED = {
    "id": "RUSTSEC-2024-0001",
    "summary": "Memory safety issue in crate.",
    "published": "2024-05-01T00:00:00Z",
    "modified": "2024-05-10T00:00:00Z",
    "aliases": ["CVE-2024-1111", "CVE-2024-2222"],
    "affected": [
        {
            "package": {"ecosystem": "crates.io", "name": "unsafe-crate"},
        },
        {
            "package": {"ecosystem": "crates.io", "name": "unsafe-crate"},
        },
    ],
}

SAMPLE_NO_ID = {
    "summary": "No ID field.",
}


@pytest.fixture
def sample_dir(tmp_path):
    pypi_dir = tmp_path / "osv_PyPI"
    pypi_dir.mkdir()
    (pypi_dir / "PYSEC-2024-1234.json").write_text(json.dumps(SAMPLE_PYSEC))

    npm_dir = tmp_path / "osv_npm"
    npm_dir.mkdir()
    (npm_dir / "GHSA-abcd-efgh-ijkl.json").write_text(json.dumps(SAMPLE_GHSA))

    crates_dir = tmp_path / "osv_crates_io"
    crates_dir.mkdir()
    (crates_dir / "RUSTSEC-2024-0001.json").write_text(json.dumps(SAMPLE_MULTI_AFFECTED))
    (crates_dir / "noid.json").write_text(json.dumps(SAMPLE_NO_ID))

    return str(tmp_path)


class TestOsvTriples:
    def test_basic_properties(self, sample_dir):
        triples = list(extract_osv_triples(sample_dir))
        ts = {t[:3] for t in triples}

        assert ("PYSEC-2024-1234", "rdf:type", "OSVulnerability") in ts
        assert ("PYSEC-2024-1234", "summary", "Arbitrary code execution in example-package.") in ts
        assert ("PYSEC-2024-1234", "date-published", "2024-03-15") in ts
        assert ("PYSEC-2024-1234", "date-modified", "2024-03-20") in ts

    def test_cve_link(self, sample_dir):
        triples = list(extract_osv_triples(sample_dir))
        ts = {t[:3] for t in triples}

        assert ("PYSEC-2024-1234", "related-cve", "CVE-2024-5678") in ts

    def test_cwe_link(self, sample_dir):
        triples = list(extract_osv_triples(sample_dir))
        ts = {t[:3] for t in triples}

        assert ("PYSEC-2024-1234", "related-weakness", "CWE-94") in ts

    def test_package_link(self, sample_dir):
        triples = list(extract_osv_triples(sample_dir))
        ts = {t[:3] for t in triples}

        assert ("PYSEC-2024-1234", "affects-package", "PyPI/example-package") in ts
        assert ("PYSEC-2024-1234", "ecosystem", "PyPI") in ts

    def test_cvss_vector(self, sample_dir):
        triples = list(extract_osv_triples(sample_dir))
        ts = {t[:3] for t in triples}

        cvss = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert ("PYSEC-2024-1234", "cvss-vector", cvss) in ts

    def test_ghsa_entry(self, sample_dir):
        triples = list(extract_osv_triples(sample_dir))
        ts = {t[:3] for t in triples}

        assert ("GHSA-abcd-efgh-ijkl", "rdf:type", "OSVulnerability") in ts
        assert ("GHSA-abcd-efgh-ijkl", "related-cve", "CVE-2024-9999") in ts
        assert ("GHSA-abcd-efgh-ijkl", "related-weakness", "CWE-79") in ts
        assert ("GHSA-abcd-efgh-ijkl", "affects-package", "npm/react-widget") in ts

    def test_multi_cve_aliases(self, sample_dir):
        triples = list(extract_osv_triples(sample_dir))
        ts = {t[:3] for t in triples}

        assert ("RUSTSEC-2024-0001", "related-cve", "CVE-2024-1111") in ts
        assert ("RUSTSEC-2024-0001", "related-cve", "CVE-2024-2222") in ts

    def test_dedup_packages(self, sample_dir):
        triples = list(extract_osv_triples(sample_dir))
        pkg_triples = [
            t for t in triples if t[0] == "RUSTSEC-2024-0001" and t[1] == "affects-package"
        ]
        assert len(pkg_triples) == 1

    def test_no_id_skipped(self, sample_dir):
        triples = list(extract_osv_triples(sample_dir))
        subjects = {t[0] for t in triples}
        assert "" not in subjects

    def test_triple_count(self, sample_dir):
        triples = list(extract_osv_triples(sample_dir))
        assert len(triples) > 15
        assert len(triples) < 100
