"""Tests for convert_loldrivers.py — LOLDrivers YAML -> SPO triples converter."""

import pytest
import yaml

from convert_loldrivers import extract_loldrivers_triples

SAMPLE_DRIVER = {
    "Id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "Tags": ["vuln_driver.sys", "vulnerable_driver"],
    "Category": "vulnerable driver",
    "Commands": [
        {
            "Command": "sc create vuln_driver binPath=...",
            "Usecase": "Load vulnerable driver",
            "Privileges": "kernel",
            "OperatingSystem": "Windows 10",
        },
    ],
    "MitreID": "T1068",
    "KnownVulnerableSamples": [
        {
            "SHA256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "SHA1": "1234567890abcdef1234567890abcdef12345678",
            "MD5": "d41d8cd98f00b204e9800998ecf8427e",
            "Company": "Acme Corp",
            "OriginalFilename": "vuln_driver.sys",
        },
    ],
    "Resources": [
        "https://example.com/loldrivers-vuln",
    ],
}

SAMPLE_DRIVER_MINIMAL = {
    "Id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
    "Tags": ["minimal_driver.sys"],
    "Category": "malicious driver",
}

SAMPLE_NO_ID = {
    "Tags": ["no_id_driver.sys"],
    "Category": "unknown",
}


@pytest.fixture
def sample_dir(tmp_path):
    yaml_dir = tmp_path / "yaml"
    yaml_dir.mkdir()
    (yaml_dir / "driver1.yaml").write_text(yaml.dump(SAMPLE_DRIVER))
    (yaml_dir / "driver2.yaml").write_text(yaml.dump(SAMPLE_DRIVER_MINIMAL))
    (yaml_dir / "noid.yaml").write_text(yaml.dump(SAMPLE_NO_ID))
    return str(tmp_path)


class TestLoldriversTriples:
    def test_basic_properties(self, sample_dir):
        triples = list(extract_loldrivers_triples(sample_dir))
        ts = {t[:3] for t in triples}
        eid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

        assert (eid, "rdf:type", "LOLDriver") in ts
        assert (eid, "name", "vuln_driver.sys") in ts
        assert (eid, "category", "vulnerable driver") in ts

    def test_technique_link(self, sample_dir):
        triples = list(extract_loldrivers_triples(sample_dir))
        ts = {t[:3] for t in triples}
        eid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

        assert (eid, "maps-to-technique", "T1068") in ts

    def test_hashes(self, sample_dir):
        triples = list(extract_loldrivers_triples(sample_dir))
        ts = {t[:3] for t in triples}
        eid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

        sha = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        assert (eid, "sha256", sha) in ts
        assert (eid, "sha1", "1234567890abcdef1234567890abcdef12345678") in ts
        assert (eid, "md5", "d41d8cd98f00b204e9800998ecf8427e") in ts

    def test_vendor_and_product(self, sample_dir):
        triples = list(extract_loldrivers_triples(sample_dir))
        ts = {t[:3] for t in triples}
        eid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

        assert (eid, "vendor", "Acme Corp") in ts
        assert (eid, "product", "vuln_driver.sys") in ts

    def test_command_properties(self, sample_dir):
        triples = list(extract_loldrivers_triples(sample_dir))
        ts = {t[:3] for t in triples}
        eid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

        assert (eid, "usecase", "Load vulnerable driver") in ts
        assert (eid, "privileges", "kernel") in ts
        assert (eid, "platform", "Windows 10") in ts

    def test_references_in_meta(self, sample_dir):
        triples = list(extract_loldrivers_triples(sample_dir))
        rdf_triples = [t for t in triples if t[0].startswith("a1b2c3d4") and t[1] == "rdf:type"]
        assert len(rdf_triples) == 1
        assert "references" in rdf_triples[0][5]

    def test_no_id_skipped(self, sample_dir):
        triples = list(extract_loldrivers_triples(sample_dir))
        subjects = {t[0] for t in triples}
        assert "" not in subjects

    def test_minimal_driver(self, sample_dir):
        triples = list(extract_loldrivers_triples(sample_dir))
        ts = {t[:3] for t in triples}
        eid = "b2c3d4e5-f6a7-8901-bcde-f12345678901"

        assert (eid, "rdf:type", "LOLDriver") in ts
        assert (eid, "name", "minimal_driver.sys") in ts
        assert (eid, "category", "malicious driver") in ts

    def test_triple_count(self, sample_dir):
        triples = list(extract_loldrivers_triples(sample_dir))
        assert len(triples) > 5
        assert len(triples) < 100
