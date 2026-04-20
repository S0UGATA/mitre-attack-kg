"""Tests for convert_nist_800_53.py — NIST 800-53 ATT&CK Mappings -> SPO triples converter."""

import json

import pytest

from convert_nist_800_53 import extract_nist_800_53_triples

SAMPLE_MAPPING = {
    "mapping_objects": [
        {
            "capability_id": "AC-2",
            "capability_description": "Account Management",
            "attack_object_id": "T1078",
            "attack_object_name": "Valid Accounts",
            "mapping_type": "mitigates",
            "score_category": "protect",
            "score_value": "significant",
        },
        {
            "capability_id": "AC-2",
            "capability_description": "Account Management",
            "attack_object_id": "T1136",
            "attack_object_name": "Create Account",
            "mapping_type": "mitigates",
            "score_category": "protect",
            "score_value": "partial",
        },
        {
            "capability_id": "SI-2",
            "capability_description": "Flaw Remediation",
            "attack_object_id": "T1190",
            "attack_object_name": "Exploit Public-Facing Application",
            "mapping_type": "mitigates",
            "score_category": "respond",
            "score_value": "significant",
        },
        {
            "capability_id": "",
            "attack_object_id": "T1059",
        },
        {
            "capability_id": "AC-3",
            "capability_description": "Access Enforcement",
            "attack_object_id": "",
        },
    ],
}


@pytest.fixture
def sample_dir(tmp_path):
    mapping_dir = (
        tmp_path / "mappings" / "nist_800_53" / "attack-16.1" / "nist_800_53-rev5" / "enterprise"
    )
    mapping_dir.mkdir(parents=True)
    (mapping_dir / "nist_800_53-rev5_attack-16.1-enterprise.json").write_text(
        json.dumps(SAMPLE_MAPPING)
    )
    return str(tmp_path)


class TestNist80053Triples:
    def test_basic_properties(self, sample_dir):
        triples = list(extract_nist_800_53_triples(sample_dir))
        ts = {t[:3] for t in triples}

        assert ("AC-2", "rdf:type", "SecurityControl") in ts
        assert ("AC-2", "name", "AC-2") in ts
        assert ("AC-2", "description", "Account Management") in ts
        assert ("AC-2", "control-family", "AC") in ts

    def test_technique_mapping(self, sample_dir):
        triples = list(extract_nist_800_53_triples(sample_dir))
        ts = {t[:3] for t in triples}

        assert ("AC-2", "mitigates-technique", "T1078") in ts
        assert ("AC-2", "mitigates-technique", "T1136") in ts

    def test_mapping_meta(self, sample_dir):
        triples = list(extract_nist_800_53_triples(sample_dir))
        mitigate_triples = [
            t
            for t in triples
            if t[0] == "AC-2" and t[1] == "mitigates-technique" and t[2] == "T1078"
        ]
        assert len(mitigate_triples) == 1
        meta = json.loads(mitigate_triples[0][5])
        assert meta["score_category"] == "protect"
        assert meta["score_value"] == "significant"

    def test_second_control(self, sample_dir):
        triples = list(extract_nist_800_53_triples(sample_dir))
        ts = {t[:3] for t in triples}

        assert ("SI-2", "rdf:type", "SecurityControl") in ts
        assert ("SI-2", "control-family", "SI") in ts
        assert ("SI-2", "mitigates-technique", "T1190") in ts

    def test_empty_fields_skipped(self, sample_dir):
        triples = list(extract_nist_800_53_triples(sample_dir))
        subjects = {t[0] for t in triples}

        assert "" not in subjects

    def test_control_emitted_once(self, sample_dir):
        triples = list(extract_nist_800_53_triples(sample_dir))
        rdf_types = [t for t in triples if t[0] == "AC-2" and t[1] == "rdf:type"]
        assert len(rdf_types) == 1

    def test_triple_count(self, sample_dir):
        triples = list(extract_nist_800_53_triples(sample_dir))
        assert len(triples) > 5
        assert len(triples) < 50
