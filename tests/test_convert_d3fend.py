"""Tests for convert_d3fend.py — MITRE D3FEND JSON-LD → SPO triples converter."""

import json

import pytest

from convert_d3fend import extract_d3fend_triples

SAMPLE_D3FEND = {
    "@context": {},
    "@graph": [
        {
            "@id": "d3f:FileEncryption",
            "d3f:d3fend-id": "D3-FE",
            "rdfs:label": "File Encryption",
            "d3f:definition": "Encrypting files to prevent unauthorized access.",
            "d3f:synonym": ["Disk Encryption", "Data Encryption"],
            "rdfs:subClassOf": [
                {"@id": "d3f:PlatformHardening"},
            ],
        },
        {
            "@id": "d3f:PlatformHardening",
            "d3f:d3fend-id": "D3-PH",
            "rdfs:label": "Platform Hardening",
            "d3f:definition": "Hardening platforms against attack.",
        },
        {
            "@id": "d3f:T1059",
            "d3f:attack-id": "T1059",
            "rdfs:label": "Command and Scripting Interpreter",
            "d3f:definition": "Adversaries may abuse command and script interpreters.",
            "rdfs:subClassOf": [
                {"@id": "d3f:ExecutionTechnique"},
            ],
        },
        {
            "@id": "d3f:T1565",
            "d3f:attack-id": "T1565",
            "rdfs:label": "Data Manipulation",
        },
        {
            # Non-d3f node, should be skipped
            "@id": "owl:Thing",
            "rdfs:label": "Thing",
        },
        {
            # D3FEND technique with counter-relationship to offensive technique
            "@id": "d3f:FileEncryptionDetect",
            "d3f:d3fend-id": "D3-FED",
            "rdfs:label": "File Encryption Detection",
            "d3f:counters": {"@id": "d3f:T1059"},
        },
    ],
}


@pytest.fixture
def sample_json_path(tmp_path):
    path = tmp_path / "d3fend.json"
    path.write_text(json.dumps(SAMPLE_D3FEND))
    return str(path)


class TestD3fendTriples:
    def test_defensive_technique(self, sample_json_path):
        triples = extract_d3fend_triples(sample_json_path)
        ts = set(triples)

        assert ("D3-FE", "rdf:type", "DefensiveTechnique") in ts
        assert ("D3-FE", "name", "File Encryption") in ts
        assert ("D3-FE", "definition", "Encrypting files to prevent unauthorized access.") in ts

    def test_synonyms(self, sample_json_path):
        triples = extract_d3fend_triples(sample_json_path)
        ts = set(triples)

        assert ("D3-FE", "synonym", "Disk Encryption") in ts
        assert ("D3-FE", "synonym", "Data Encryption") in ts

    def test_parent_relationship(self, sample_json_path):
        triples = extract_d3fend_triples(sample_json_path)
        ts = set(triples)

        assert ("D3-FE", "child-of", "PlatformHardening") in ts

    def test_offensive_technique(self, sample_json_path):
        triples = extract_d3fend_triples(sample_json_path)
        ts = set(triples)

        assert ("T1059", "rdf:type", "OffensiveTechnique") in ts
        assert ("T1059", "d3fend-name", "Command and Scripting Interpreter") in ts
        defn = "Adversaries may abuse command and script interpreters."
        assert ("T1059", "d3fend-definition", defn) in ts

    def test_offensive_parent(self, sample_json_path):
        triples = extract_d3fend_triples(sample_json_path)
        ts = set(triples)

        assert ("T1059", "child-of", "ExecutionTechnique") in ts

    def test_non_d3f_skipped(self, sample_json_path):
        triples = extract_d3fend_triples(sample_json_path)
        subjects = {s for s, _, _ in triples}

        assert "owl:Thing" not in subjects

    def test_counters_relationship(self, sample_json_path):
        triples = extract_d3fend_triples(sample_json_path)
        ts = set(triples)

        assert ("D3-FED", "counters", "T1059") in ts

    def test_multiple_techniques(self, sample_json_path):
        triples = extract_d3fend_triples(sample_json_path)
        defensive = [(s, p, o) for s, p, o in triples if o == "DefensiveTechnique"]
        offensive = [(s, p, o) for s, p, o in triples if o == "OffensiveTechnique"]

        assert len(defensive) == 3  # D3-FE, D3-PH, D3-FED
        assert len(offensive) == 2  # T1059, T1565

    def test_empty_graph(self, tmp_path):
        path = tmp_path / "empty.json"
        path.write_text(json.dumps({"@context": {}, "@graph": []}))
        triples = extract_d3fend_triples(str(path))
        assert triples == []
