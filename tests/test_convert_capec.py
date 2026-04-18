"""Tests for convert_capec.py — CAPEC XML → SPO triples converter."""

import pytest

from convert_capec import extract_capec_triples

SAMPLE_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3"
                        Name="CAPEC" Version="3.9" Date="2024-01-01">
  <Attack_Patterns>
    <Attack_Pattern ID="66" Name="SQL Injection" Abstraction="Standard" Status="Stable">
      <Description>An attacker exploits SQL injection.</Description>
      <Likelihood_Of_Attack>High</Likelihood_Of_Attack>
      <Typical_Severity>High</Typical_Severity>
      <Related_Attack_Patterns>
        <Related_Attack_Pattern Nature="ChildOf" CAPEC_ID="248"/>
      </Related_Attack_Patterns>
      <Related_Weaknesses>
        <Related_Weakness CWE_ID="89"/>
        <Related_Weakness CWE_ID="1286"/>
      </Related_Weaknesses>
      <Taxonomy_Mappings>
        <Taxonomy_Mapping Taxonomy_Name="ATTACK">
          <Entry_ID>1190.002</Entry_ID>
          <Entry_Name>Exploit Public-Facing Application</Entry_Name>
        </Taxonomy_Mapping>
      </Taxonomy_Mappings>
      <Consequences>
        <Consequence>
          <Scope>Confidentiality</Scope>
          <Impact>Read Data</Impact>
        </Consequence>
      </Consequences>
    </Attack_Pattern>
    <Attack_Pattern ID="999" Name="Old Pattern" Abstraction="Meta" Status="Deprecated">
      <Description>This is deprecated.</Description>
    </Attack_Pattern>
  </Attack_Patterns>
</Attack_Pattern_Catalog>
"""


@pytest.fixture
def sample_xml_path(tmp_path):
    path = tmp_path / "sample.xml"
    path.write_text(SAMPLE_XML)
    return str(path)


class TestCapecTriples:
    def test_basic_properties(self, sample_xml_path):
        triples = extract_capec_triples(sample_xml_path)
        ts = {t[:3] for t in triples}

        assert ("CAPEC-66", "rdf:type", "AttackPattern") in ts
        assert ("CAPEC-66", "name", "SQL Injection") in ts
        assert ("CAPEC-66", "abstraction", "Standard") in ts
        assert ("CAPEC-66", "status", "Stable") in ts
        assert ("CAPEC-66", "likelihood", "High") in ts
        assert ("CAPEC-66", "severity", "High") in ts

    def test_description(self, sample_xml_path):
        triples = extract_capec_triples(sample_xml_path)
        desc = [o for s, p, o, *_ in triples if s == "CAPEC-66" and p == "description"]
        assert len(desc) == 1
        assert "SQL injection" in desc[0]

    def test_relationships(self, sample_xml_path):
        triples = extract_capec_triples(sample_xml_path)
        ts = {t[:3] for t in triples}

        assert ("CAPEC-66", "child-of", "CAPEC-248") in ts
        assert ("CAPEC-66", "related-weakness", "CWE-89") in ts
        assert ("CAPEC-66", "related-weakness", "CWE-1286") in ts
        assert ("CAPEC-66", "maps-to-technique", "T1190.002") in ts

    def test_consequences(self, sample_xml_path):
        triples = extract_capec_triples(sample_xml_path)
        ts = {t[:3] for t in triples}

        assert ("CAPEC-66", "consequence-scope", "Confidentiality") in ts
        assert ("CAPEC-66", "consequence-impact", "Read Data") in ts

    def test_deprecated_excluded(self, sample_xml_path):
        triples = extract_capec_triples(sample_xml_path)
        subjects = {t[0] for t in triples}

        assert "CAPEC-999" not in subjects

    def test_triple_count(self, sample_xml_path):
        triples = extract_capec_triples(sample_xml_path)
        assert len(triples) > 5
        assert len(triples) < 50

    def test_six_tuple_source_and_object_type(self, sample_xml_path):
        """Verify source, object_type, and meta fields in 6-tuple output."""
        triples = extract_capec_triples(sample_xml_path)

        # All triples must have source="capec"
        assert all(t[3] == "capec" for t in triples)

        # Check object_type for specific predicates
        by_pred = {}
        for t in triples:
            by_pred.setdefault(t[1], t)

        assert by_pred["rdf:type"][4] == "enum"
        assert by_pred["name"][4] == "string"
        assert by_pred["abstraction"][4] == "enum"
        assert by_pred["status"][4] == "enum"
        assert by_pred["likelihood"][4] == "enum"
        assert by_pred["severity"][4] == "enum"
        assert by_pred["description"][4] == "string"
        assert by_pred["child-of"][4] == "id"
        assert by_pred["related-weakness"][4] == "id"
        assert by_pred["maps-to-technique"][4] == "id"
        assert by_pred["consequence-scope"][4] == "string"
        assert by_pred["consequence-impact"][4] == "string"

        # Property triples should have empty meta
        assert by_pred["name"][5] == ""
        assert by_pred["description"][5] == ""
