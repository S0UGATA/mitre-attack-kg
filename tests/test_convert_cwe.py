"""Tests for convert_cwe.py — CWE XML → SPO triples converter."""

import pytest

from convert_cwe import extract_cwe_triples

SAMPLE_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7"
                  Name="CWE" Version="4.19" Date="2024-01-01">
  <Weaknesses>
    <Weakness ID="79" Name="Cross-site Scripting (XSS)" Abstraction="Base"
              Structure="Simple" Status="Stable">
      <Description>The product does not neutralize user input.</Description>
      <Likelihood_Of_Exploit>High</Likelihood_Of_Exploit>
      <Related_Weaknesses>
        <Related_Weakness Nature="ChildOf" CWE_ID="74" View_ID="1000"/>
        <Related_Weakness Nature="CanPrecede" CWE_ID="494" View_ID="1000"/>
      </Related_Weaknesses>
      <Related_Attack_Patterns>
        <Related_Attack_Pattern CAPEC_ID="86"/>
        <Related_Attack_Pattern CAPEC_ID="198"/>
      </Related_Attack_Patterns>
      <Applicable_Platforms>
        <Language Name="JavaScript" Prevalence="Often"/>
        <Technology Class="Web Based" Prevalence="Often"/>
      </Applicable_Platforms>
      <Common_Consequences>
        <Consequence>
          <Scope>Confidentiality</Scope>
          <Scope>Integrity</Scope>
          <Impact>Execute Unauthorized Code or Commands</Impact>
        </Consequence>
      </Common_Consequences>
      <Modes_Of_Introduction>
        <Introduction>
          <Phase>Implementation</Phase>
        </Introduction>
      </Modes_Of_Introduction>
    </Weakness>
    <Weakness ID="999" Name="Old Weakness" Abstraction="Base"
              Structure="Simple" Status="Deprecated">
      <Description>This is deprecated.</Description>
    </Weakness>
  </Weaknesses>
</Weakness_Catalog>
"""


@pytest.fixture
def sample_xml_path(tmp_path):
    path = tmp_path / "sample.xml"
    path.write_text(SAMPLE_XML)
    return str(path)


class TestCweTriples:
    def test_basic_properties(self, sample_xml_path):
        triples = extract_cwe_triples(sample_xml_path)
        ts = set(triples)

        assert ("CWE-79", "rdf:type", "Weakness") in ts
        assert ("CWE-79", "name", "Cross-site Scripting (XSS)") in ts
        assert ("CWE-79", "abstraction", "Base") in ts
        assert ("CWE-79", "status", "Stable") in ts
        assert ("CWE-79", "likelihood-of-exploit", "High") in ts

    def test_description(self, sample_xml_path):
        triples = extract_cwe_triples(sample_xml_path)
        desc = [o for s, p, o in triples if s == "CWE-79" and p == "description"]
        assert len(desc) == 1
        assert "neutralize" in desc[0]

    def test_cwe_relationships(self, sample_xml_path):
        triples = extract_cwe_triples(sample_xml_path)
        ts = set(triples)

        assert ("CWE-79", "child-of", "CWE-74") in ts
        assert ("CWE-79", "can-precede", "CWE-494") in ts

    def test_capec_relationships(self, sample_xml_path):
        triples = extract_cwe_triples(sample_xml_path)
        ts = set(triples)

        assert ("CWE-79", "related-attack-pattern", "CAPEC-86") in ts
        assert ("CWE-79", "related-attack-pattern", "CAPEC-198") in ts

    def test_platforms(self, sample_xml_path):
        triples = extract_cwe_triples(sample_xml_path)
        ts = set(triples)

        assert ("CWE-79", "platform", "JavaScript") in ts
        assert ("CWE-79", "platform", "Web Based") in ts

    def test_consequences(self, sample_xml_path):
        triples = extract_cwe_triples(sample_xml_path)
        ts = set(triples)

        assert ("CWE-79", "consequence-scope", "Confidentiality") in ts
        assert ("CWE-79", "consequence-scope", "Integrity") in ts
        assert ("CWE-79", "consequence-impact", "Execute Unauthorized Code or Commands") in ts

    def test_introduction_phase(self, sample_xml_path):
        triples = extract_cwe_triples(sample_xml_path)
        ts = set(triples)

        assert ("CWE-79", "introduction-phase", "Implementation") in ts

    def test_deprecated_excluded(self, sample_xml_path):
        triples = extract_cwe_triples(sample_xml_path)
        subjects = {s for s, _, _ in triples}

        assert "CWE-999" not in subjects

    def test_triple_count(self, sample_xml_path):
        triples = extract_cwe_triples(sample_xml_path)
        assert len(triples) > 5
        assert len(triples) < 50
