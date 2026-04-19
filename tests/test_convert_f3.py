"""Tests for convert_f3.py — MITRE F3 STIX 2.1 → SPO triples converter."""

import json

import pytest

from convert_f3 import extract_f3_triples

SAMPLE_F3_BUNDLE = {
    "type": "bundle",
    "id": "bundle--test",
    "objects": [
        {
            "type": "x-mitre-tactic",
            "id": "x-mitre-tactic--001",
            "name": "Positioning",
            "description": "Actions after access to prepare for fraud execution.",
            "created": "2026-04-02T19:15:57.686Z",
            "modified": "2026-04-08T17:36:46.308Z",
            "external_references": [
                {
                    "source_name": "mitre-f3",
                    "url": "https://ctid.mitre.org/fraud/#/tactics/FA0001",
                    "external_id": "FA0001",
                }
            ],
            "x_mitre_shortname": "positioning",
        },
        {
            "type": "x-mitre-tactic",
            "id": "x-mitre-tactic--002",
            "name": "Monetization",
            "description": "Converting stolen assets into usable funds.",
            "external_references": [
                {
                    "source_name": "mitre-f3",
                    "url": "https://ctid.mitre.org/fraud/#/tactics/FA0002",
                    "external_id": "FA0002",
                }
            ],
            "x_mitre_shortname": "monetization",
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--001",
            "name": "Account Takeover",
            "description": "Gaining unauthorized access to victim accounts.",
            "created": "2026-04-02T19:15:57.686Z",
            "modified": "2026-04-08T17:36:46.310Z",
            "kill_chain_phases": [{"kill_chain_name": "mitre-f3", "phase_name": "positioning"}],
            "external_references": [
                {
                    "source_name": "mitre-f3",
                    "url": "https://ctid.mitre.org/fraud/techniques/F1001",
                    "external_id": "F1001",
                }
            ],
            "x_mitre_is_subtechnique": False,
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--002",
            "name": "Credential Stuffing",
            "description": "Using stolen credentials to access accounts.",
            "kill_chain_phases": [{"kill_chain_name": "mitre-f3", "phase_name": "positioning"}],
            "external_references": [
                {
                    "source_name": "mitre-f3",
                    "url": "https://ctid.mitre.org/fraud/techniques/F1001.001",
                    "external_id": "F1001.001",
                }
            ],
            "x_mitre_is_subtechnique": True,
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--003",
            "name": "Brute Force",
            "description": "ATT&CK-borrowed technique used in fraud.",
            "kill_chain_phases": [{"kill_chain_name": "mitre-f3", "phase_name": "positioning"}],
            "external_references": [
                {
                    "source_name": "mitre-f3",
                    "url": "https://ctid.mitre.org/fraud/techniques/T1110",
                    "external_id": "T1110",
                }
            ],
            "x_mitre_is_subtechnique": False,
        },
        {
            "type": "relationship",
            "id": "relationship--001",
            "relationship_type": "subtechnique-of",
            "source_ref": "attack-pattern--002",
            "target_ref": "attack-pattern--001",
        },
        {
            "type": "x-mitre-matrix",
            "id": "x-mitre-matrix--001",
            "name": "F3 Matrix",
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--no-extref",
            "name": "No External Ref Technique",
        },
    ],
}


@pytest.fixture
def sample_json_path(tmp_path):
    path = tmp_path / "f3-stix.json"
    path.write_text(json.dumps(SAMPLE_F3_BUNDLE))
    return str(path)


class TestF3Triples:
    def test_tactic_properties(self, sample_json_path):
        triples = extract_f3_triples(sample_json_path)
        ts = {t[:3] for t in triples}

        assert ("FA0001", "rdf:type", "Tactic") in ts
        assert ("FA0001", "name", "Positioning") in ts
        assert (
            "FA0001",
            "description",
            "Actions after access to prepare for fraud execution.",
        ) in ts
        assert ("FA0001", "created", "2026-04-02T19:15:57.686Z") in ts
        assert ("FA0001", "modified", "2026-04-08T17:36:46.308Z") in ts
        assert ("FA0001", "shortname", "positioning") in ts

    def test_tactic_without_dates(self, sample_json_path):
        triples = extract_f3_triples(sample_json_path)
        ts = {t[:3] for t in triples}

        assert ("FA0002", "rdf:type", "Tactic") in ts
        assert ("FA0002", "name", "Monetization") in ts
        fa0002_preds = {p for s, p, o in ts if s == "FA0002"}
        assert "created" not in fa0002_preds
        assert "modified" not in fa0002_preds

    def test_technique_properties(self, sample_json_path):
        triples = extract_f3_triples(sample_json_path)
        ts = {t[:3] for t in triples}

        assert ("F1001", "rdf:type", "Technique") in ts
        assert ("F1001", "name", "Account Takeover") in ts
        assert ("F1001", "description", "Gaining unauthorized access to victim accounts.") in ts
        assert ("F1001", "created", "2026-04-02T19:15:57.686Z") in ts
        assert ("F1001", "url", "https://ctid.mitre.org/fraud/techniques/F1001") in ts

    def test_technique_tactic_link(self, sample_json_path):
        triples = extract_f3_triples(sample_json_path)
        ts = {t[:3] for t in triples}

        assert ("F1001", "belongs-to-tactic", "FA0001") in ts
        assert ("T1110", "belongs-to-tactic", "FA0001") in ts

    def test_subtechnique(self, sample_json_path):
        triples = extract_f3_triples(sample_json_path)
        ts = {t[:3] for t in triples}

        assert ("F1001.001", "rdf:type", "Technique") in ts
        assert ("F1001.001", "is-subtechnique", "true") in ts
        assert ("F1001.001", "subtechnique-of", "F1001") in ts

    def test_attack_borrowed_technique(self, sample_json_path):
        triples = extract_f3_triples(sample_json_path)
        ts = {t[:3] for t in triples}

        assert ("T1110", "rdf:type", "Technique") in ts
        assert ("T1110", "name", "Brute Force") in ts

    def test_no_extref_uses_stix_id(self, sample_json_path):
        triples = extract_f3_triples(sample_json_path)
        ts = {t[:3] for t in triples}

        assert ("attack-pattern--no-extref", "rdf:type", "Technique") in ts
        assert ("attack-pattern--no-extref", "name", "No External Ref Technique") in ts

    def test_matrix_ignored(self, sample_json_path):
        triples = extract_f3_triples(sample_json_path)
        subjects = {s for s, p, o, *_ in triples}

        assert "x-mitre-matrix--001" not in subjects

    def test_source_is_f3(self, sample_json_path):
        triples = extract_f3_triples(sample_json_path)
        sources = {t[3] for t in triples}

        assert sources == {"f3"}

    def test_triple_count(self, sample_json_path):
        triples = extract_f3_triples(sample_json_path)
        assert len(triples) > 15
        assert len(triples) < 100
