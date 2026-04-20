"""Tests for convert_atomic.py — Atomic Red Team YAML -> SPO triples converter."""

import pytest
import yaml

from convert_atomic import extract_atomic_triples

SAMPLE_TECHNIQUE = {
    "attack_technique": "T1059.001",
    "display_name": "Command and Scripting Interpreter: PowerShell",
    "atomic_tests": [
        {
            "name": "Mimikatz - Creds",
            "auto_generated_guid": "aaaa1111-bbbb-cccc-dddd-eeeeffffaaaa",
            "description": "Download and execute Mimikatz.",
            "supported_platforms": ["windows"],
            "executor": {"name": "powershell", "command": "IEX ..."},
        },
        {
            "name": "BloodHound",
            "auto_generated_guid": "bbbb2222-cccc-dddd-eeee-ffffaaaabbbb",
            "description": "Run BloodHound collection.",
            "supported_platforms": ["windows"],
            "executor": {"name": "command_prompt", "command": "SharpHound.exe ..."},
        },
    ],
}

SAMPLE_TECHNIQUE_MULTI_PLATFORM = {
    "attack_technique": "T1016",
    "display_name": "System Network Configuration Discovery",
    "atomic_tests": [
        {
            "name": "System Network Config Discovery on Linux",
            "auto_generated_guid": "cccc3333-dddd-eeee-ffff-aaaabbbbcccc",
            "description": "Discover network configuration on Linux.",
            "supported_platforms": ["linux", "macos"],
            "executor": {"name": "sh", "command": "ifconfig"},
        },
    ],
}

SAMPLE_TECHNIQUE_NO_GUID = {
    "attack_technique": "T1234",
    "display_name": "Some technique",
    "atomic_tests": [
        {
            "name": "Test without GUID",
            "description": "Missing auto_generated_guid.",
        },
    ],
}


@pytest.fixture
def sample_dir(tmp_path):
    atomics = tmp_path / "atomics"
    t1059_dir = atomics / "T1059.001"
    t1059_dir.mkdir(parents=True)
    (t1059_dir / "T1059.001.yaml").write_text(yaml.dump(SAMPLE_TECHNIQUE))

    t1016_dir = atomics / "T1016"
    t1016_dir.mkdir(parents=True)
    (t1016_dir / "T1016.yaml").write_text(yaml.dump(SAMPLE_TECHNIQUE_MULTI_PLATFORM))

    t1234_dir = atomics / "T1234"
    t1234_dir.mkdir(parents=True)
    (t1234_dir / "T1234.yaml").write_text(yaml.dump(SAMPLE_TECHNIQUE_NO_GUID))

    return str(tmp_path)


class TestAtomicTriples:
    def test_basic_properties(self, sample_dir):
        triples = list(extract_atomic_triples(sample_dir))
        ts = {t[:3] for t in triples}
        eid = "aaaa1111-bbbb-cccc-dddd-eeeeffffaaaa"

        assert (eid, "rdf:type", "AtomicTest") in ts
        assert (eid, "name", "Mimikatz - Creds") in ts
        assert (eid, "description", "Download and execute Mimikatz.") in ts

    def test_technique_link(self, sample_dir):
        triples = list(extract_atomic_triples(sample_dir))
        ts = {t[:3] for t in triples}

        assert ("aaaa1111-bbbb-cccc-dddd-eeeeffffaaaa", "tests-technique", "T1059.001") in ts
        assert ("bbbb2222-cccc-dddd-eeee-ffffaaaabbbb", "tests-technique", "T1059.001") in ts

    def test_platform(self, sample_dir):
        triples = list(extract_atomic_triples(sample_dir))
        ts = {t[:3] for t in triples}
        eid = "aaaa1111-bbbb-cccc-dddd-eeeeffffaaaa"

        assert (eid, "platform", "windows") in ts

    def test_multi_platform(self, sample_dir):
        triples = list(extract_atomic_triples(sample_dir))
        ts = {t[:3] for t in triples}
        eid = "cccc3333-dddd-eeee-ffff-aaaabbbbcccc"

        assert (eid, "platform", "linux") in ts
        assert (eid, "platform", "macos") in ts

    def test_executor(self, sample_dir):
        triples = list(extract_atomic_triples(sample_dir))
        ts = {t[:3] for t in triples}

        assert ("aaaa1111-bbbb-cccc-dddd-eeeeffffaaaa", "executor", "powershell") in ts
        assert ("bbbb2222-cccc-dddd-eeee-ffffaaaabbbb", "executor", "command_prompt") in ts

    def test_no_guid_skipped(self, sample_dir):
        triples = list(extract_atomic_triples(sample_dir))
        subjects = {t[0] for t in triples}
        assert "" not in subjects

    def test_triple_count(self, sample_dir):
        triples = list(extract_atomic_triples(sample_dir))
        assert len(triples) > 10
        assert len(triples) < 100
