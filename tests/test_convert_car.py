"""Tests for convert_car.py — MITRE CAR YAML → SPO triples converter."""

import pytest
import yaml

from convert_car import extract_car_triples

SAMPLE_ANALYTIC_1 = {
    "id": "CAR-2024-01-001",
    "title": "Suspicious PowerShell Commands",
    "description": "Detects suspicious PowerShell command-line arguments.",
    "submission_date": "2024-01-15",
    "information_domain": "Host",
    "platforms": ["Windows"],
    "subtypes": ["Process"],
    "analytic_types": ["Situational Awareness"],
    "coverage": [
        {
            "technique": "T1059",
            "coverage": "Moderate",
            "tactics": ["Execution"],
            "subtechniques": ["T1059.001"],
        },
    ],
    "d3fend_mappings": [
        {"id": "D3-PSA"},
    ],
}

SAMPLE_ANALYTIC_2 = {
    "id": "CAR-2024-02-001",
    "title": "Registry Modification",
    "description": "Detects registry modifications for persistence.",
    "platforms": ["Windows", "Linux"],
    "coverage": [
        {
            "technique": "T1547",
            "coverage": "Low",
            "tactics": ["Persistence"],
            "subtechniques": ["T1547.001", "T1547.002"],
        },
        {
            "technique": "T1112",
            "tactics": ["Defense Evasion"],
        },
    ],
}

SAMPLE_ANALYTIC_NO_ID = {
    "title": "No ID Analytics",
    "description": "This has no id field.",
}


@pytest.fixture
def sample_analytics_dir(tmp_path):
    # Mimic extraction layout: <extract_dir>/car-master/analytics/
    d = tmp_path / "car-master" / "analytics"
    d.mkdir(parents=True)
    (d / "CAR-2024-01-001.yaml").write_text(yaml.dump(SAMPLE_ANALYTIC_1))
    (d / "CAR-2024-02-001.yaml").write_text(yaml.dump(SAMPLE_ANALYTIC_2))
    (d / "no-id.yaml").write_text(yaml.dump(SAMPLE_ANALYTIC_NO_ID))
    return str(tmp_path)


class TestCarTriples:
    def test_basic_properties(self, sample_analytics_dir):
        triples = extract_car_triples(sample_analytics_dir)
        ts = set(triples)

        assert ("CAR-2024-01-001", "rdf:type", "Analytic") in ts
        assert ("CAR-2024-01-001", "title", "Suspicious PowerShell Commands") in ts
        assert ("CAR-2024-01-001", "information-domain", "Host") in ts
        assert ("CAR-2024-01-001", "submission-date", "2024-01-15") in ts

    def test_description(self, sample_analytics_dir):
        triples = extract_car_triples(sample_analytics_dir)
        desc = [o for s, p, o in triples if s == "CAR-2024-01-001" and p == "description"]
        assert len(desc) == 1
        assert "PowerShell" in desc[0]

    def test_platform(self, sample_analytics_dir):
        triples = extract_car_triples(sample_analytics_dir)
        ts = set(triples)

        assert ("CAR-2024-01-001", "platform", "Windows") in ts
        assert ("CAR-2024-02-001", "platform", "Windows") in ts
        assert ("CAR-2024-02-001", "platform", "Linux") in ts

    def test_subtypes_and_analytic_types(self, sample_analytics_dir):
        triples = extract_car_triples(sample_analytics_dir)
        ts = set(triples)

        assert ("CAR-2024-01-001", "subtype", "Process") in ts
        assert ("CAR-2024-01-001", "analytic-type", "Situational Awareness") in ts

    def test_technique_detection(self, sample_analytics_dir):
        triples = extract_car_triples(sample_analytics_dir)
        ts = set(triples)

        assert ("CAR-2024-01-001", "detects-technique", "T1059") in ts
        assert ("CAR-2024-01-001", "coverage-level", "T1059:Moderate") in ts
        assert ("CAR-2024-01-001", "covers-tactic", "Execution") in ts
        assert ("CAR-2024-01-001", "detects-subtechnique", "T1059.001") in ts

    def test_multiple_coverage(self, sample_analytics_dir):
        triples = extract_car_triples(sample_analytics_dir)
        ts = set(triples)

        assert ("CAR-2024-02-001", "detects-technique", "T1547") in ts
        assert ("CAR-2024-02-001", "detects-technique", "T1112") in ts
        assert ("CAR-2024-02-001", "detects-subtechnique", "T1547.001") in ts
        assert ("CAR-2024-02-001", "detects-subtechnique", "T1547.002") in ts

    def test_d3fend_mapping(self, sample_analytics_dir):
        triples = extract_car_triples(sample_analytics_dir)
        ts = set(triples)

        assert ("CAR-2024-01-001", "maps-to-d3fend", "D3-PSA") in ts

    def test_no_id_skipped(self, sample_analytics_dir):
        triples = extract_car_triples(sample_analytics_dir)
        subjects = {s for s, _, _ in triples}

        assert "" not in subjects
        assert "No ID Analytics" not in subjects

    def test_triple_count(self, sample_analytics_dir):
        triples = extract_car_triples(sample_analytics_dir)
        assert len(triples) > 10
        assert len(triples) < 100
