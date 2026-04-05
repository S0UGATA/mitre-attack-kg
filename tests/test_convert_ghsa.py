"""Tests for convert_ghsa.py — GitHub Security Advisories JSON → SPO triples converter."""

import json

import pytest

from convert_ghsa import extract_ghsa_triples

SAMPLE_ADVISORY_1 = {
    "schema_version": "1.4.0",
    "id": "GHSA-xxxx-yyyy-zzzz",
    "modified": "2024-01-20T00:00:00Z",
    "published": "2024-01-15T00:00:00Z",
    "aliases": ["CVE-2024-1234"],
    "summary": "XSS vulnerability in example-package",
    "details": "A cross-site scripting vulnerability exists ...",
    "severity": [
        {
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        }
    ],
    "affected": [
        {
            "package": {"ecosystem": "npm", "name": "example-package"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "2.0.1"}],
                }
            ],
        },
        {
            "package": {"ecosystem": "npm", "name": "example-package-core"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "3.0.0"}, {"fixed": "3.1.0"}],
                }
            ],
        },
    ],
    "database_specific": {
        "cwe_ids": ["CWE-79"],
        "severity": "MODERATE",
        "github_reviewed": True,
    },
}

SAMPLE_ADVISORY_2 = {
    "id": "GHSA-aaaa-bbbb-cccc",
    "aliases": ["CVE-2024-5678", "CVE-2024-5679"],
    "summary": "SQL Injection in db-lib",
    "published": "2024-02-01T00:00:00Z",
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "db-lib"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "1.0"}, {"fixed": "1.2.3"}],
                }
            ],
        }
    ],
    "database_specific": {
        "cwe_ids": ["CWE-89", "CWE-90"],
        "severity": "HIGH",
    },
}

SAMPLE_ADVISORY_NO_ID = {
    "summary": "Advisory without ID",
}


@pytest.fixture
def sample_advisory_dir(tmp_path):
    # Mimic extraction layout: <extract_dir>/advisory-database-main/advisories/github-reviewed/
    reviewed = tmp_path / "advisory-database-main" / "advisories" / "github-reviewed"

    d1 = reviewed / "2024" / "01" / "GHSA-xxxx-yyyy-zzzz"
    d1.mkdir(parents=True)
    (d1 / "GHSA-xxxx-yyyy-zzzz.json").write_text(json.dumps(SAMPLE_ADVISORY_1))

    d2 = reviewed / "2024" / "02" / "GHSA-aaaa-bbbb-cccc"
    d2.mkdir(parents=True)
    (d2 / "GHSA-aaaa-bbbb-cccc.json").write_text(json.dumps(SAMPLE_ADVISORY_2))

    d3 = reviewed / "2024" / "03" / "no-id"
    d3.mkdir(parents=True)
    (d3 / "GHSA-noid-noid-noid.json").write_text(json.dumps(SAMPLE_ADVISORY_NO_ID))

    return str(tmp_path)


class TestGhsaTriples:
    def test_basic_properties(self, sample_advisory_dir):
        triples = list(extract_ghsa_triples(sample_advisory_dir))
        ts = set(triples)

        assert ("GHSA-xxxx-yyyy-zzzz", "rdf:type", "SecurityAdvisory") in ts
        assert ("GHSA-xxxx-yyyy-zzzz", "summary", "XSS vulnerability in example-package") in ts
        assert ("GHSA-xxxx-yyyy-zzzz", "date-published", "2024-01-15T00:00:00Z") in ts
        assert ("GHSA-xxxx-yyyy-zzzz", "date-modified", "2024-01-20T00:00:00Z") in ts

    def test_cve_aliases(self, sample_advisory_dir):
        triples = list(extract_ghsa_triples(sample_advisory_dir))
        ts = set(triples)

        assert ("GHSA-xxxx-yyyy-zzzz", "related-cve", "CVE-2024-1234") in ts

    def test_multiple_cve_aliases(self, sample_advisory_dir):
        triples = list(extract_ghsa_triples(sample_advisory_dir))
        ts = set(triples)

        assert ("GHSA-aaaa-bbbb-cccc", "related-cve", "CVE-2024-5678") in ts
        assert ("GHSA-aaaa-bbbb-cccc", "related-cve", "CVE-2024-5679") in ts

    def test_severity(self, sample_advisory_dir):
        triples = list(extract_ghsa_triples(sample_advisory_dir))
        ts = set(triples)

        assert ("GHSA-xxxx-yyyy-zzzz", "severity", "MODERATE") in ts
        assert ("GHSA-aaaa-bbbb-cccc", "severity", "HIGH") in ts

    def test_cwe_ids(self, sample_advisory_dir):
        triples = list(extract_ghsa_triples(sample_advisory_dir))
        ts = set(triples)

        assert ("GHSA-xxxx-yyyy-zzzz", "related-weakness", "CWE-79") in ts
        assert ("GHSA-aaaa-bbbb-cccc", "related-weakness", "CWE-89") in ts
        assert ("GHSA-aaaa-bbbb-cccc", "related-weakness", "CWE-90") in ts

    def test_affected_packages(self, sample_advisory_dir):
        triples = list(extract_ghsa_triples(sample_advisory_dir))
        ts = set(triples)

        assert ("GHSA-xxxx-yyyy-zzzz", "affects-package", "npm/example-package") in ts
        assert ("GHSA-xxxx-yyyy-zzzz", "affects-package", "npm/example-package-core") in ts
        assert ("GHSA-aaaa-bbbb-cccc", "affects-package", "PyPI/db-lib") in ts

    def test_fixed_versions(self, sample_advisory_dir):
        triples = list(extract_ghsa_triples(sample_advisory_dir))
        ts = set(triples)

        assert ("GHSA-xxxx-yyyy-zzzz", "fixed-in", "npm/example-package@2.0.1") in ts
        assert ("GHSA-xxxx-yyyy-zzzz", "fixed-in", "npm/example-package-core@3.1.0") in ts
        assert ("GHSA-aaaa-bbbb-cccc", "fixed-in", "PyPI/db-lib@1.2.3") in ts

    def test_cvss_vector(self, sample_advisory_dir):
        triples = list(extract_ghsa_triples(sample_advisory_dir))
        ts = set(triples)

        assert (
            "GHSA-xxxx-yyyy-zzzz",
            "cvss-vector",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        ) in ts

    def test_no_id_skipped(self, sample_advisory_dir):
        triples = list(extract_ghsa_triples(sample_advisory_dir))
        subjects = {s for s, _, _ in triples}

        assert "" not in subjects

    def test_triple_count(self, sample_advisory_dir):
        triples = list(extract_ghsa_triples(sample_advisory_dir))
        assert len(triples) > 10
        assert len(triples) < 100
