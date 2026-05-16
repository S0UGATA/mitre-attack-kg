"""Tests for convert_euvd.py — EUVD JSON -> SPO triples converter."""

import json

import pytest

from convert_euvd import extract_euvd_triples

# The EUVD /api/kev/dump endpoint returns only 4 fields per record.
SAMPLE_VULN = {
    "euvdId": "EUVD-2025-4893",
    "cveId": "CVE-2025-1234",
    "dateAdded": "2025-01-15",
    "sources": ["cisa_kev"],
}

SAMPLE_VULN_MINIMAL = {
    "euvdId": "EUVD-2025-0001",
    "cveId": "CVE-2025-0001",
    "dateAdded": "2025-02-01",
    "sources": [],
}

SAMPLE_NO_CVE = {
    "euvdId": "EUVD-2025-9999",
    "dateAdded": "2025-03-01",
    "sources": ["enisa"],
}

SAMPLE_NO_ID = {
    "cveId": "CVE-2025-0000",
    "dateAdded": "2025-04-01",
}


@pytest.fixture
def sample_file(tmp_path):
    data = [SAMPLE_VULN, SAMPLE_VULN_MINIMAL, SAMPLE_NO_CVE, SAMPLE_NO_ID]
    path = tmp_path / "euvd_dump.json"
    path.write_text(json.dumps(data))
    return str(path)


class TestEuvdTriples:
    def test_basic_properties(self, sample_file):
        triples = list(extract_euvd_triples(sample_file))
        ts = {t[:3] for t in triples}

        assert ("EUVD-2025-4893", "rdf:type", "EUVulnerability") in ts
        assert ("EUVD-2025-4893", "related-cve", "CVE-2025-1234") in ts
        assert ("EUVD-2025-4893", "date-published", "2025-01-15") in ts

    def test_sources_in_meta(self, sample_file):
        triples = list(extract_euvd_triples(sample_file))
        type_triples = [t for t in triples if t[0] == "EUVD-2025-4893" and t[1] == "rdf:type"]
        assert len(type_triples) == 1
        meta = json.loads(type_triples[0][5])
        assert meta["sources"] == ["cisa_kev"]

    def test_empty_sources_no_meta(self, sample_file):
        triples = list(extract_euvd_triples(sample_file))
        type_triples = [t for t in triples if t[0] == "EUVD-2025-0001" and t[1] == "rdf:type"]
        assert len(type_triples) == 1
        assert type_triples[0][5] == ""  # no meta when sources is empty

    def test_cve_id_uppercased(self, sample_file):
        triples = list(extract_euvd_triples(sample_file))
        cve_objs = [t[2] for t in triples if t[0] == "EUVD-2025-4893" and t[1] == "related-cve"]
        assert cve_objs == ["CVE-2025-1234"]

    def test_no_cve_still_emits_type(self, sample_file):
        triples = list(extract_euvd_triples(sample_file))
        ts = {t[:3] for t in triples}
        assert ("EUVD-2025-9999", "rdf:type", "EUVulnerability") in ts
        # No related-cve when cveId absent
        assert not any(t[0] == "EUVD-2025-9999" and t[1] == "related-cve" for t in triples)

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
        # EUVD-2025-4893: rdf:type + related-cve + date-published = 3
        # EUVD-2025-0001: rdf:type + related-cve + date-published = 3
        # EUVD-2025-9999: rdf:type + date-published = 2
        # SAMPLE_NO_ID: skipped
        assert len(triples) == 8
