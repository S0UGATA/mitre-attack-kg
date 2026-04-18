"""Tests for convert_engage.py — MITRE ENGAGE JSON → SPO triples converter."""

import json

import pytest

from convert_engage import extract_engage_triples

SAMPLE_ENGAGE = [
    {
        "attack_id": "T1001",
        "attack_technique": "Data Obfuscation",
        "eav_id": "EAV0001",
        "eav": "Adversary uses protocol manipulation to hide C2",
        "eac": "Software Manipulation",
        "eac_id": "EAC0001",
    },
    {
        "attack_id": "T1001",
        "attack_technique": "Data Obfuscation",
        "eav_id": "EAV0002",
        "eav": "Adversary modifies traffic patterns",
        "eac": "Software Manipulation",
        "eac_id": "EAC0001",
    },
    {
        "attack_id": "T1059",
        "attack_technique": "Command and Scripting Interpreter",
        "eav_id": "EAV0001",
        "eav": "Adversary uses protocol manipulation to hide C2",
        "eac": "Lure",
        "eac_id": "EAC0002",
    },
]


@pytest.fixture
def sample_json_path(tmp_path):
    path = tmp_path / "engage.json"
    path.write_text(json.dumps(SAMPLE_ENGAGE))
    return str(path)


class TestEngageTriples:
    def test_eac_entity(self, sample_json_path):
        triples = extract_engage_triples(sample_json_path)
        ts = {t[:3] for t in triples}

        assert ("EAC0001", "rdf:type", "EngagementActivity") in ts
        assert ("EAC0001", "name", "Software Manipulation") in ts
        assert ("EAC0002", "rdf:type", "EngagementActivity") in ts
        assert ("EAC0002", "name", "Lure") in ts

    def test_eav_entity(self, sample_json_path):
        triples = extract_engage_triples(sample_json_path)
        ts = {t[:3] for t in triples}

        assert ("EAV0001", "rdf:type", "AdversaryVulnerability") in ts
        assert ("EAV0002", "rdf:type", "AdversaryVulnerability") in ts

    def test_eac_deduplicated(self, sample_json_path):
        triples = extract_engage_triples(sample_json_path)
        # EAC0001 appears twice in input but rdf:type should only appear once
        type_triples = [t[:3] for t in triples if t[0] == "EAC0001" and t[1] == "rdf:type"]
        assert len(type_triples) == 1

    def test_eav_deduplicated(self, sample_json_path):
        triples = extract_engage_triples(sample_json_path)
        # EAV0001 appears twice in input but rdf:type should only appear once
        type_triples = [t[:3] for t in triples if t[0] == "EAV0001" and t[1] == "rdf:type"]
        assert len(type_triples) == 1

    def test_engages_technique(self, sample_json_path):
        triples = extract_engage_triples(sample_json_path)
        ts = {t[:3] for t in triples}

        assert ("EAC0001", "engages-technique", "T1001") in ts
        assert ("EAC0002", "engages-technique", "T1059") in ts

    def test_exploits_vulnerability(self, sample_json_path):
        triples = extract_engage_triples(sample_json_path)
        ts = {t[:3] for t in triples}

        assert ("EAV0001", "vulnerability-of", "T1001") in ts
        assert ("EAV0002", "vulnerability-of", "T1001") in ts

    def test_addresses_vulnerability(self, sample_json_path):
        triples = extract_engage_triples(sample_json_path)
        ts = {t[:3] for t in triples}

        assert ("EAC0001", "addresses-vulnerability", "EAV0001") in ts
        assert ("EAC0001", "addresses-vulnerability", "EAV0002") in ts

    def test_empty_input(self, tmp_path):
        path = tmp_path / "empty.json"
        path.write_text("[]")
        triples = extract_engage_triples(str(path))
        assert triples == []
