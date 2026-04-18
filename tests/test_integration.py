"""Integration tests — require network access to download MITRE ATT&CK STIX data.

Run:  python -m pytest tests/test_integration.py -v
Skip: python -m pytest tests/ -v --ignore=tests/test_integration.py
"""

import pytest

from convert_attack import convert_domain

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def enterprise_df(tmp_path_factory):
    """Download and convert enterprise domain once for all tests."""
    output_dir = tmp_path_factory.mktemp("output")
    return convert_domain("enterprise", output_dir)


# ---------------------------------------------------------------------------
# Integration: fetch real data, convert, verify triple count
# ---------------------------------------------------------------------------


class TestIntegration:
    def test_triple_count_range(self, enterprise_df):
        """Enterprise domain should produce 30k-100k triples."""
        assert 30_000 < len(enterprise_df) < 100_000

    def test_schema(self, enterprise_df):
        """DataFrame should have the expected SPO columns."""
        assert list(enterprise_df.columns) == [
            "subject",
            "predicate",
            "object",
            "source",
            "object_type",
            "meta",
        ]


# ---------------------------------------------------------------------------
# Spot checks: verify known relationships in real ATT&CK data
# ---------------------------------------------------------------------------


class TestSpotChecks:
    def test_apt29_uses_techniques(self, enterprise_df):
        """APT29 (G0016) should use techniques."""
        uses = enterprise_df[
            (enterprise_df.subject == "G0016") & (enterprise_df.predicate == "uses")
        ]
        assert len(uses) > 0

    def test_subtechnique_relationship(self, enterprise_df):
        """T1059.001 should be subtechnique-of T1059."""
        rel = enterprise_df[
            (enterprise_df.subject == "T1059.001")
            & (enterprise_df.predicate == "subtechnique-of")
            & (enterprise_df.object == "T1059")
        ]
        assert len(rel) == 1

    def test_mitigation_exists(self, enterprise_df):
        """Known mitigation M1049 should mitigate at least one technique."""
        mitigates = enterprise_df[
            (enterprise_df.subject == "M1049") & (enterprise_df.predicate == "mitigates")
        ]
        assert len(mitigates) > 0

    def test_tactic_linkage_uses_attack_ids(self, enterprise_df):
        """belongs-to-tactic should use tactic ATT&CK IDs (TAxxxx), not shortnames."""
        tactic_links = enterprise_df[enterprise_df.predicate == "belongs-to-tactic"]
        assert len(tactic_links) > 0
        for val in tactic_links.object.unique():
            assert val.startswith("TA"), f"Expected tactic ID like TA0002, got '{val}'"


# ---------------------------------------------------------------------------
# Count validation: entity type counts should be in reasonable ranges
# ---------------------------------------------------------------------------


class TestCountValidation:
    @pytest.fixture(scope="class")
    def type_counts(self, enterprise_df):
        types = enterprise_df[enterprise_df.predicate == "rdf:type"]
        return types.object.value_counts()

    def test_technique_count(self, type_counts):
        assert type_counts.get("Technique", 0) > 100

    def test_tactic_count(self, type_counts):
        assert type_counts.get("Tactic", 0) >= 10

    def test_group_count(self, type_counts):
        assert type_counts.get("Group", 0) > 50

    def test_software_count(self, type_counts):
        assert type_counts.get("Malware", 0) + type_counts.get("Tool", 0) > 50

    def test_relationship_types_present(self, enterprise_df):
        preds = set(enterprise_df.predicate.unique())
        for rel in ["uses", "mitigates", "subtechnique-of", "detects"]:
            assert rel in preds, f"Expected relationship type '{rel}' not found"


# ---------------------------------------------------------------------------
# HuggingFace: verify Parquet files are loadable via datasets library
# ---------------------------------------------------------------------------


class TestHuggingFaceLoad:
    def test_parquet_loadable_as_dataset(self, enterprise_df, tmp_path_factory):
        """Parquet output should be loadable by HuggingFace datasets library."""
        datasets = pytest.importorskip("datasets")

        ds = datasets.Dataset.from_pandas(enterprise_df)
        assert list(ds.features.keys()) == [
            "subject",
            "predicate",
            "object",
            "source",
            "object_type",
            "meta",
        ]
        assert len(ds) == len(enterprise_df)
        assert len(ds) > 30_000
