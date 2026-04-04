"""Tests for convert_kev.py — CISA KEV JSON → SPO triples converter."""

import json

import pytest

from convert_kev import extract_kev_triples

SAMPLE_KEV = {
    "title": "CISA KEV Catalog",
    "catalogVersion": "2024.01.01",
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-1234",
            "vendorProject": "Microsoft",
            "product": "Windows",
            "vulnerabilityName": "Windows Privilege Escalation",
            "shortDescription": "A privilege escalation vulnerability in Windows.",
            "dateAdded": "2024-01-15",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2024-02-05",
            "knownRansomwareCampaignUse": "Known",
            "notes": "See vendor advisory.",
            "cwes": ["CWE-269"],
        },
        {
            "cveID": "CVE-2024-5678",
            "vendorProject": "Apache",
            "product": "HTTP Server",
            "vulnerabilityName": "Apache RCE",
            "dateAdded": "2024-03-01",
            "dueDate": "2024-03-22",
            "knownRansomwareCampaignUse": "Unknown",
        },
        {
            # Entry without cveID should be skipped
            "vendorProject": "NoCVE",
        },
    ],
}


@pytest.fixture
def sample_json_path(tmp_path):
    path = tmp_path / "kev.json"
    path.write_text(json.dumps(SAMPLE_KEV))
    return str(path)


class TestKevTriples:
    def test_basic_properties(self, sample_json_path):
        triples = extract_kev_triples(sample_json_path)
        ts = set(triples)

        assert ("CVE-2024-1234", "rdf:type", "KnownExploitedVulnerability") in ts
        assert ("CVE-2024-1234", "kev-vendor", "Microsoft") in ts
        assert ("CVE-2024-1234", "kev-product", "Windows") in ts
        assert ("CVE-2024-1234", "kev-name", "Windows Privilege Escalation") in ts
        assert ("CVE-2024-1234", "kev-date-added", "2024-01-15") in ts
        assert ("CVE-2024-1234", "kev-due-date", "2024-02-05") in ts

    def test_description(self, sample_json_path):
        triples = extract_kev_triples(sample_json_path)
        desc = [o for s, p, o in triples if s == "CVE-2024-1234" and p == "kev-description"]
        assert len(desc) == 1
        assert "privilege escalation" in desc[0].lower()

    def test_ransomware_and_notes(self, sample_json_path):
        triples = extract_kev_triples(sample_json_path)
        ts = set(triples)

        assert ("CVE-2024-1234", "kev-ransomware-use", "Known") in ts
        assert ("CVE-2024-1234", "kev-notes", "See vendor advisory.") in ts

    def test_required_action(self, sample_json_path):
        triples = extract_kev_triples(sample_json_path)
        ts = set(triples)

        action = "Apply updates per vendor instructions."
        assert ("CVE-2024-1234", "kev-required-action", action) in ts

    def test_cwe_cross_link(self, sample_json_path):
        triples = extract_kev_triples(sample_json_path)
        ts = set(triples)

        assert ("CVE-2024-1234", "related-weakness", "CWE-269") in ts

    def test_second_vuln(self, sample_json_path):
        triples = extract_kev_triples(sample_json_path)
        ts = set(triples)

        assert ("CVE-2024-5678", "rdf:type", "KnownExploitedVulnerability") in ts
        assert ("CVE-2024-5678", "kev-vendor", "Apache") in ts

    def test_no_cve_id_skipped(self, sample_json_path):
        triples = extract_kev_triples(sample_json_path)
        subjects = {s for s, _, _ in triples}

        assert "NoCVE" not in subjects
        assert "" not in subjects

    def test_triple_count(self, sample_json_path):
        triples = extract_kev_triples(sample_json_path)
        assert len(triples) > 5
        assert len(triples) < 50
