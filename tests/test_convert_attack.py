"""Tests for convert.py — MITRE ATT&CK STIX → SPO triples converter."""

from unittest.mock import MagicMock, patch

import pandas as pd
import pytest

from common import triples_to_dataframe
from convert_attack import (
    _entity_triples,
    _resolve_id,
    convert_domain,
    extract_triples,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


class FakeStixObject:
    """Minimal stand-in for a STIX domain object."""

    def __init__(self, stix_id, name, obj_type="attack-pattern", **kwargs):
        self.id = stix_id
        self.name = name
        self.type = obj_type
        self.created = "2024-01-01T00:00:00Z"
        self.modified = "2024-06-01T00:00:00Z"
        for k, v in kwargs.items():
            setattr(self, k, v)


class FakeRelationship:
    """Minimal stand-in for a STIX Relationship object."""

    def __init__(self, source_ref, rel_type, target_ref):
        self.source_ref = source_ref
        self.relationship_type = rel_type
        self.target_ref = target_ref


class FakeKillChainPhase:
    def __init__(self, kill_chain_name, phase_name):
        self.kill_chain_name = kill_chain_name
        self.phase_name = phase_name


class FakeExternalRef:
    def __init__(self, url):
        self.url = url


@pytest.fixture
def fake_attack():
    """Build a mock MitreAttackData with minimal test data."""
    attack = MagicMock()

    # ID resolution map
    id_map = {
        "attack-pattern--aaa": "T1059.001",
        "attack-pattern--bbb": "T1059",
        "x-mitre-tactic--ccc": "TA0002",
        "intrusion-set--ddd": "G0016",
        "malware--eee": "S0154",
        "tool--fff": "S0005",
        "course-of-action--ggg": "M1049",
        "campaign--hhh": "C0018",
        "x-mitre-data-source--iii": "DS0009",
        "x-mitre-data-component--jjj": "DC0001",
    }
    attack.get_attack_id.side_effect = lambda sid: id_map.get(sid)

    # Techniques
    t1 = FakeStixObject(
        "attack-pattern--aaa",
        "PowerShell",
        x_mitre_platforms=["Windows"],
        x_mitre_domains=["enterprise-attack"],
        x_mitre_is_subtechnique=True,
        kill_chain_phases=[FakeKillChainPhase("mitre-attack", "execution")],
        external_references=[FakeExternalRef("https://attack.mitre.org/techniques/T1059/001")],
    )
    t2 = FakeStixObject(
        "attack-pattern--bbb",
        "Command and Scripting Interpreter",
        x_mitre_platforms=["Windows", "Linux", "macOS"],
        x_mitre_is_subtechnique=False,
    )
    attack.get_techniques.return_value = [t1, t2]

    # Tactics
    tactic = FakeStixObject(
        "x-mitre-tactic--ccc",
        "Execution",
        obj_type="x-mitre-tactic",
        x_mitre_shortname="execution",
    )
    attack.get_tactics.return_value = [tactic]

    # Groups
    group = FakeStixObject(
        "intrusion-set--ddd",
        "APT29",
        obj_type="intrusion-set",
        aliases=["APT29", "Cozy Bear", "The Dukes"],
    )
    attack.get_groups.return_value = [group]

    # Software (malware + tool)
    malware = FakeStixObject("malware--eee", "Cobalt Strike", obj_type="malware")
    tool = FakeStixObject("tool--fff", "PsExec", obj_type="tool")
    attack.get_software.return_value = [malware, tool]

    # Mitigations
    mitigation = FakeStixObject(
        "course-of-action--ggg", "Antivirus/Antimalware", obj_type="course-of-action"
    )
    attack.get_mitigations.return_value = [mitigation]

    # Campaigns
    campaign = FakeStixObject("campaign--hhh", "C0018", obj_type="campaign")
    attack.get_campaigns.return_value = [campaign]

    # Data sources / components
    ds = FakeStixObject("x-mitre-data-source--iii", "Process", obj_type="x-mitre-data-source")
    attack.get_datasources.return_value = [ds]

    dc = FakeStixObject(
        "x-mitre-data-component--jjj", "Process Creation", obj_type="x-mitre-data-component"
    )
    attack.get_datacomponents.return_value = [dc]

    # Relationships
    rels = [
        FakeRelationship("intrusion-set--ddd", "uses", "attack-pattern--aaa"),
        FakeRelationship("course-of-action--ggg", "mitigates", "attack-pattern--aaa"),
        FakeRelationship("attack-pattern--aaa", "subtechnique-of", "attack-pattern--bbb"),
        FakeRelationship("x-mitre-data-component--jjj", "detects", "attack-pattern--aaa"),
    ]
    attack.get_objects_by_type.return_value = rels

    return attack


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestResolveId:
    def test_known_id(self, fake_attack):
        assert _resolve_id(fake_attack, "attack-pattern--aaa") == "T1059.001"

    def test_unknown_falls_back_to_stix_id(self, fake_attack):
        assert _resolve_id(fake_attack, "unknown--zzz") == "unknown--zzz"


class TestEntityTriples:
    @pytest.fixture
    def tactic_map(self):
        return {"execution": "TA0002"}

    def test_technique_triples(self, fake_attack, tactic_map):
        obj = fake_attack.get_techniques()[0]
        triples = _entity_triples(fake_attack, obj, "Technique", tactic_map)

        subjects = {t[0] for t in triples}
        assert subjects == {"T1059.001"}

        preds = {t[1] for t in triples}
        assert "rdf:type" in preds
        assert "name" in preds
        assert "platform" in preds
        assert "belongs-to-tactic" in preds
        assert "is-subtechnique" in preds
        assert "url" in preds

        # Verify specific values
        triple_set = set(triples)
        assert ("T1059.001", "rdf:type", "Technique") in triple_set
        assert ("T1059.001", "name", "PowerShell") in triple_set
        assert ("T1059.001", "platform", "Windows") in triple_set
        assert ("T1059.001", "belongs-to-tactic", "TA0002") in triple_set
        assert ("T1059.001", "is-subtechnique", "True") in triple_set
        assert ("T1059.001", "url", "https://attack.mitre.org/techniques/T1059/001") in triple_set

    def test_group_aliases(self, fake_attack):
        obj = fake_attack.get_groups()[0]
        triples = _entity_triples(fake_attack, obj, "Group")

        alias_triples = [(s, p, o) for s, p, o in triples if p == "alias"]
        alias_values = {o for _, _, o in alias_triples}
        # "APT29" is the name so should NOT appear as alias
        assert "APT29" not in alias_values
        assert "Cozy Bear" in alias_values
        assert "The Dukes" in alias_values

    def test_tactic_shortname(self, fake_attack):
        obj = fake_attack.get_tactics()[0]
        triples = _entity_triples(fake_attack, obj, "Tactic")
        assert ("TA0002", "shortname", "execution") in set(triples)


class TestExtractTriples:
    def test_contains_entity_and_relationship_triples(self, fake_attack):
        triples = extract_triples(fake_attack)

        # Should have entity triples
        triple_set = set(triples)
        assert ("T1059.001", "rdf:type", "Technique") in triple_set
        assert ("G0016", "name", "APT29") in triple_set
        assert ("S0154", "rdf:type", "Malware") in triple_set
        assert ("S0005", "rdf:type", "Tool") in triple_set

        # Should have relationship triples
        assert ("G0016", "uses", "T1059.001") in triple_set
        assert ("M1049", "mitigates", "T1059.001") in triple_set
        assert ("T1059.001", "subtechnique-of", "T1059") in triple_set
        assert ("DC0001", "detects", "T1059.001") in triple_set

    def test_triple_count(self, fake_attack):
        triples = extract_triples(fake_attack)
        # Just verify we get a reasonable number (not empty, not astronomical)
        assert len(triples) > 30
        assert len(triples) < 500


class TestTriplesToDataframe:
    def test_schema(self):
        triples = [
            ("T1059", "rdf:type", "Technique"),
            ("T1059", "name", "Command and Scripting Interpreter"),
        ]
        df = triples_to_dataframe(triples)
        assert list(df.columns) == ["subject", "predicate", "object"]
        assert len(df) == 2

    def test_values(self):
        triples = [("G0016", "uses", "T1059.001")]
        df = triples_to_dataframe(triples)
        assert df.iloc[0]["subject"] == "G0016"
        assert df.iloc[0]["predicate"] == "uses"
        assert df.iloc[0]["object"] == "T1059.001"


class TestConvertDomain:
    @patch("convert_attack.download_stix")
    @patch("convert_attack.MitreAttackData")
    def test_produces_parquet(self, mock_mad_cls, mock_download, fake_attack, tmp_path):
        mock_download.return_value = "/tmp/fake.json"
        mock_mad_cls.return_value = fake_attack

        df = convert_domain("enterprise", tmp_path)

        out_file = tmp_path / "enterprise.parquet"
        assert out_file.exists()
        loaded = pd.read_parquet(out_file)
        assert list(loaded.columns) == ["subject", "predicate", "object"]
        assert len(loaded) == len(df)
        assert len(loaded) > 0
