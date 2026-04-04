"""Tests for convert_sigma.py — SigmaHQ YAML → SPO triples converter."""

import pytest
import yaml

from convert_sigma import extract_sigma_triples

SAMPLE_RULE_1 = {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "title": "Suspicious PowerShell Download",
    "description": "Detects PowerShell download cradles.",
    "status": "stable",
    "level": "high",
    "author": "Security Researcher",
    "date": "2024-01-15",
    "logsource": {
        "category": "process_creation",
        "product": "windows",
    },
    "detection": {"selection": {"CommandLine|contains": "IEX"}},
    "tags": [
        "attack.execution",
        "attack.t1059.001",
        "attack.t1059",
        "cve.2024.1234",
    ],
}

SAMPLE_RULE_2 = {
    "id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
    "title": "SSH Brute Force",
    "description": "Detects SSH brute force attempts.",
    "status": "test",
    "level": "medium",
    "author": "Another Author",
    "date": "2024-02-01",
    "logsource": {
        "category": "network_connection",
        "product": "linux",
        "service": "sshd",
    },
    "detection": {"selection": {"DestinationPort": 22}},
    "tags": [
        "attack.t1110",
        "attack.credential_access",
    ],
}

SAMPLE_RULE_NO_ID = {
    "title": "Rule Without ID",
    "description": "This has no id field.",
}


@pytest.fixture
def sample_rules_dir(tmp_path):
    d = tmp_path / "rules"
    d.mkdir()
    (d / "rule1.yml").write_text(yaml.dump(SAMPLE_RULE_1))
    (d / "rule2.yml").write_text(yaml.dump(SAMPLE_RULE_2))
    (d / "noid.yml").write_text(yaml.dump(SAMPLE_RULE_NO_ID))
    return str(d)


class TestSigmaTriples:
    def test_basic_properties(self, sample_rules_dir):
        triples = list(extract_sigma_triples(sample_rules_dir))
        ts = set(triples)
        rule_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

        assert (rule_id, "rdf:type", "SigmaRule") in ts
        assert (rule_id, "title", "Suspicious PowerShell Download") in ts
        assert (rule_id, "status", "stable") in ts
        assert (rule_id, "level", "high") in ts
        assert (rule_id, "author", "Security Researcher") in ts
        assert (rule_id, "date", "2024-01-15") in ts

    def test_description(self, sample_rules_dir):
        triples = list(extract_sigma_triples(sample_rules_dir))
        rule_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        desc = [o for s, p, o in triples if s == rule_id and p == "description"]
        assert len(desc) == 1
        assert "PowerShell" in desc[0]

    def test_logsource(self, sample_rules_dir):
        triples = list(extract_sigma_triples(sample_rules_dir))
        ts = set(triples)
        rule_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

        assert (rule_id, "logsource-category", "process_creation") in ts
        assert (rule_id, "logsource-product", "windows") in ts

    def test_logsource_service(self, sample_rules_dir):
        triples = list(extract_sigma_triples(sample_rules_dir))
        ts = set(triples)
        rule_id = "b2c3d4e5-f6a7-8901-bcde-f12345678901"

        assert (rule_id, "logsource-service", "sshd") in ts

    def test_attack_technique_tags(self, sample_rules_dir):
        triples = list(extract_sigma_triples(sample_rules_dir))
        ts = set(triples)
        rule_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

        assert (rule_id, "detects-technique", "T1059.001") in ts
        assert (rule_id, "detects-technique", "T1059") in ts

    def test_cve_tags(self, sample_rules_dir):
        triples = list(extract_sigma_triples(sample_rules_dir))
        ts = set(triples)
        rule_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

        assert (rule_id, "related-cve", "CVE-2024-1234") in ts

    def test_second_rule(self, sample_rules_dir):
        triples = list(extract_sigma_triples(sample_rules_dir))
        ts = set(triples)
        rule_id = "b2c3d4e5-f6a7-8901-bcde-f12345678901"

        assert (rule_id, "rdf:type", "SigmaRule") in ts
        assert (rule_id, "detects-technique", "T1110") in ts

    def test_no_id_skipped(self, sample_rules_dir):
        triples = list(extract_sigma_triples(sample_rules_dir))
        subjects = {s for s, _, _ in triples}

        assert "" not in subjects

    def test_tactic_tags_not_techniques(self, sample_rules_dir):
        """Tactic tags like attack.execution should not create detects-technique triples."""
        triples = list(extract_sigma_triples(sample_rules_dir))
        technique_objs = {o for _, p, o in triples if p == "detects-technique"}

        # "execution" and "credential_access" are tactics, not techniques
        assert "execution" not in technique_objs
        assert "credential_access" not in technique_objs

    def test_triple_count(self, sample_rules_dir):
        triples = list(extract_sigma_triples(sample_rules_dir))
        assert len(triples) > 10
        assert len(triples) < 100
