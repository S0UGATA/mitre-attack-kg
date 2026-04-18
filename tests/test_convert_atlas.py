"""Tests for convert_atlas.py — MITRE ATLAS YAML → SPO triples converter."""

import pytest
import yaml

from convert_atlas import extract_atlas_triples

SAMPLE_ATLAS = {
    "matrices": [
        {
            "id": "ATLAS",
            "name": "ATLAS Matrix",
            "tactics": [
                {
                    "id": "AML.TA0001",
                    "name": "ML Model Access",
                    "description": "Gaining access to ML models.",
                    "created_date": "2023-01-01",
                    "modified_date": "2023-06-15",
                    "ATT&CK-reference": {"id": "TA0001"},
                },
                {
                    "id": "AML.TA0002",
                    "name": "ML Attack Staging",
                },
            ],
            "techniques": [
                {
                    "id": "AML.T0000",
                    "name": "ML Supply Chain Compromise",
                    "description": "Adversaries may manipulate ML supply chains.",
                    "created_date": "2023-01-01",
                    "modified_date": "2023-06-15",
                    "maturity": "Reviewed",
                    "tactics": ["AML.TA0001"],
                    "ATT&CK-reference": {"id": "T1195"},
                },
                {
                    "id": "AML.T0000.001",
                    "name": "ML Supply Chain Compromise: Model Poisoning",
                    "description": "Subtechnique of supply chain compromise.",
                    "subtechnique-of": "AML.T0000",
                    "tactics": ["AML.TA0001"],
                },
                {
                    # Technique with no ID should be skipped
                    "name": "No ID Technique",
                },
            ],
        },
    ],
    "case-studies": [
        {
            "id": "AML.CS0001",
            "name": "Evasion of ML Malware Detector",
            "description": "Adversary evaded ML-based malware detector.",
            "techniques": ["AML.T0000", "AML.T0000.001"],
        },
    ],
    "mitigations": [
        {
            "id": "AML.M0001",
            "name": "Model Validation",
            "description": "Validate ML models before deployment.",
            "techniques": ["AML.T0000"],
        },
    ],
}


@pytest.fixture
def sample_yaml_path(tmp_path):
    path = tmp_path / "ATLAS.yaml"
    path.write_text(yaml.dump(SAMPLE_ATLAS))
    return str(path)


class TestAtlasTriples:
    def test_tactic_properties(self, sample_yaml_path):
        triples = extract_atlas_triples(sample_yaml_path)
        ts = {t[:3] for t in triples}

        assert ("AML.TA0001", "rdf:type", "Tactic") in ts
        assert ("AML.TA0001", "name", "ML Model Access") in ts
        assert ("AML.TA0001", "description", "Gaining access to ML models.") in ts
        assert ("AML.TA0001", "created", "2023-01-01") in ts
        assert ("AML.TA0001", "modified", "2023-06-15") in ts

    def test_tactic_attack_reference(self, sample_yaml_path):
        triples = extract_atlas_triples(sample_yaml_path)
        ts = {t[:3] for t in triples}

        assert ("AML.TA0001", "related-attack-tactic", "TA0001") in ts

    def test_technique_properties(self, sample_yaml_path):
        triples = extract_atlas_triples(sample_yaml_path)
        ts = {t[:3] for t in triples}

        assert ("AML.T0000", "rdf:type", "Technique") in ts
        assert ("AML.T0000", "name", "ML Supply Chain Compromise") in ts
        assert ("AML.T0000", "maturity", "Reviewed") in ts

    def test_technique_tactic_link(self, sample_yaml_path):
        triples = extract_atlas_triples(sample_yaml_path)
        ts = {t[:3] for t in triples}

        assert ("AML.T0000", "belongs-to-tactic", "AML.TA0001") in ts

    def test_technique_attack_reference(self, sample_yaml_path):
        triples = extract_atlas_triples(sample_yaml_path)
        ts = {t[:3] for t in triples}

        assert ("AML.T0000", "related-attack-technique", "T1195") in ts

    def test_subtechnique(self, sample_yaml_path):
        triples = extract_atlas_triples(sample_yaml_path)
        ts = {t[:3] for t in triples}

        assert ("AML.T0000.001", "rdf:type", "Technique") in ts
        assert ("AML.T0000.001", "subtechnique-of", "AML.T0000") in ts

    def test_case_study(self, sample_yaml_path):
        triples = extract_atlas_triples(sample_yaml_path)
        ts = {t[:3] for t in triples}

        assert ("AML.CS0001", "rdf:type", "CaseStudy") in ts
        assert ("AML.CS0001", "name", "Evasion of ML Malware Detector") in ts
        assert ("AML.CS0001", "uses-technique", "AML.T0000") in ts
        assert ("AML.CS0001", "uses-technique", "AML.T0000.001") in ts

    def test_mitigation(self, sample_yaml_path):
        triples = extract_atlas_triples(sample_yaml_path)
        ts = {t[:3] for t in triples}

        assert ("AML.M0001", "rdf:type", "Mitigation") in ts
        assert ("AML.M0001", "name", "Model Validation") in ts
        assert ("AML.M0001", "mitigates", "AML.T0000") in ts

    def test_no_id_skipped(self, sample_yaml_path):
        triples = extract_atlas_triples(sample_yaml_path)
        names = [o for s, p, o, *_ in triples if p == "name"]
        assert "No ID Technique" not in names

    def test_triple_count(self, sample_yaml_path):
        triples = extract_atlas_triples(sample_yaml_path)
        assert len(triples) > 10
        assert len(triples) < 100
