"""Tests for convert_misp_galaxy.py — MISP Galaxy JSON → SPO triples converter."""

import json

import pytest

from convert_misp_galaxy import extract_misp_galaxy_triples

SAMPLE_THREAT_ACTOR = {
    "type": "threat-actor",
    "uuid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    "values": [
        {
            "value": "APT1",
            "uuid": "11111111-1111-1111-1111-111111111111",
            "description": "PLA Unit 61398 Chinese state-sponsored group.",
            "meta": {
                "country": "CN",
                "cfr-suspected-state-sponsor": "China",
                "cfr-suspected-victims": ["United States", "Canada"],
                "cfr-target-category": ["Government", "Private sector"],
                "attribution-confidence": "50",
                "synonyms": ["Comment Crew", "G0006"],
                "refs": ["https://example.com/apt1"],
            },
            "related": [
                {
                    "dest-uuid": "22222222-2222-2222-2222-222222222222",
                    "type": "similar-to",
                },
                {
                    "dest-uuid": "33333333-3333-3333-3333-333333333333",
                    "type": "uses",
                },
                {
                    "dest-uuid": "44444444-4444-4444-4444-444444444444",
                    "type": "custom-rel",
                },
            ],
        },
        {
            # Entry without uuid should be skipped
            "value": "NoUUID Actor",
            "description": "This should be skipped.",
        },
    ],
}

SAMPLE_RANSOMWARE = {
    "type": "ransomware",
    "uuid": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
    "values": [
        {
            "value": "WannaCry",
            "uuid": "55555555-5555-5555-5555-555555555555",
            "description": "A devastating ransomware worm.",
            "meta": {
                "synonyms": ["WCry", "WanaCrypt0r"],
            },
            "related": [
                {
                    "dest-uuid": "66666666-6666-6666-6666-666666666666",
                    "type": "variant-of",
                },
            ],
        },
    ],
}

SAMPLE_MITRE_ATTACK_PATTERN = {
    "type": "mitre-attack-pattern",
    "uuid": "cccccccc-cccc-cccc-cccc-cccccccccccc",
    "values": [
        {
            "value": "PowerShell - T1059.001",
            "uuid": "77777777-7777-7777-7777-777777777777",
            "description": "Adversaries may abuse PowerShell.",
            "meta": {
                "external_id": "T1059.001",
                "kill_chain": ["mitre-attack:execution"],
            },
            "related": [
                {
                    "dest-uuid": "88888888-8888-8888-8888-888888888888",
                    "type": "subtechnique-of",
                },
            ],
        },
    ],
}

SAMPLE_CANCER = {
    "type": "cancer",
    "uuid": "dddddddd-dddd-dddd-dddd-dddddddddddd",
    "values": [
        {
            "value": "Some Cancer Type",
            "uuid": "99999999-9999-9999-9999-999999999999",
            "description": "Not security-relevant.",
        },
    ],
}


@pytest.fixture
def sample_clusters_dir(tmp_path):
    """Create a mock directory structure mimicking an extracted MISP Galaxy repo."""
    clusters = tmp_path / "misp-galaxy-main" / "clusters"
    clusters.mkdir(parents=True)

    (clusters / "threat-actor.json").write_text(json.dumps(SAMPLE_THREAT_ACTOR))
    (clusters / "ransomware.json").write_text(json.dumps(SAMPLE_RANSOMWARE))
    (clusters / "mitre-attack-pattern.json").write_text(json.dumps(SAMPLE_MITRE_ATTACK_PATTERN))
    (clusters / "cancer.json").write_text(json.dumps(SAMPLE_CANCER))

    return str(tmp_path / "misp-galaxy-main")


class TestMispGalaxyTriples:
    def test_basic_properties(self, sample_clusters_dir):
        triples = list(extract_misp_galaxy_triples(sample_clusters_dir))
        ts = set(triples)

        subj = "misp:11111111-1111-1111-1111-111111111111"
        assert (subj, "rdf:type", "ThreatActor") in ts
        assert (subj, "name", "APT1") in ts
        assert (subj, "description", "PLA Unit 61398 Chinese state-sponsored group.") in ts
        assert (subj, "galaxy", "threat-actor") in ts

    def test_synonyms(self, sample_clusters_dir):
        triples = list(extract_misp_galaxy_triples(sample_clusters_dir))
        ts = set(triples)

        subj = "misp:11111111-1111-1111-1111-111111111111"
        assert (subj, "synonym", "Comment Crew") in ts
        assert (subj, "synonym", "G0006") in ts

    def test_country(self, sample_clusters_dir):
        triples = list(extract_misp_galaxy_triples(sample_clusters_dir))
        ts = set(triples)

        subj = "misp:11111111-1111-1111-1111-111111111111"
        assert (subj, "country", "CN") in ts
        assert (subj, "cfr-suspected-state-sponsor", "China") in ts

    def test_targets_country(self, sample_clusters_dir):
        triples = list(extract_misp_galaxy_triples(sample_clusters_dir))
        ts = set(triples)

        subj = "misp:11111111-1111-1111-1111-111111111111"
        assert (subj, "targets-country", "United States") in ts
        assert (subj, "targets-country", "Canada") in ts

    def test_targets_sector(self, sample_clusters_dir):
        triples = list(extract_misp_galaxy_triples(sample_clusters_dir))
        ts = set(triples)

        subj = "misp:11111111-1111-1111-1111-111111111111"
        assert (subj, "targets-sector", "Government") in ts
        assert (subj, "targets-sector", "Private sector") in ts

    def test_attribution_confidence(self, sample_clusters_dir):
        triples = list(extract_misp_galaxy_triples(sample_clusters_dir))
        ts = set(triples)

        subj = "misp:11111111-1111-1111-1111-111111111111"
        assert (subj, "attribution-confidence", "50") in ts

    def test_related_similar(self, sample_clusters_dir):
        triples = list(extract_misp_galaxy_triples(sample_clusters_dir))
        ts = set(triples)

        subj = "misp:11111111-1111-1111-1111-111111111111"
        assert (subj, "similar-to", "misp:22222222-2222-2222-2222-222222222222") in ts

    def test_related_uses(self, sample_clusters_dir):
        triples = list(extract_misp_galaxy_triples(sample_clusters_dir))
        ts = set(triples)

        subj = "misp:11111111-1111-1111-1111-111111111111"
        assert (subj, "uses", "misp:33333333-3333-3333-3333-333333333333") in ts

    def test_related_fallback(self, sample_clusters_dir):
        triples = list(extract_misp_galaxy_triples(sample_clusters_dir))
        ts = set(triples)

        subj = "misp:11111111-1111-1111-1111-111111111111"
        assert (subj, "misp-related", "misp:44444444-4444-4444-4444-444444444444") in ts

    def test_ransomware_entry(self, sample_clusters_dir):
        triples = list(extract_misp_galaxy_triples(sample_clusters_dir))
        ts = set(triples)

        subj = "misp:55555555-5555-5555-5555-555555555555"
        assert (subj, "rdf:type", "Ransomware") in ts
        assert (subj, "name", "WannaCry") in ts
        assert (subj, "synonym", "WCry") in ts
        assert (subj, "variant-of", "misp:66666666-6666-6666-6666-666666666666") in ts

    def test_mitre_cluster_skips_entity_triples(self, sample_clusters_dir):
        triples = list(extract_misp_galaxy_triples(sample_clusters_dir))
        ts = set(triples)

        subj = "misp:77777777-7777-7777-7777-777777777777"
        # Should NOT have entity properties
        assert (subj, "rdf:type", "MitreAttackPattern") not in ts
        assert (subj, "name", "PowerShell - T1059.001") not in ts
        assert (subj, "description", "Adversaries may abuse PowerShell.") not in ts

    def test_mitre_cluster_emits_cross_link(self, sample_clusters_dir):
        triples = list(extract_misp_galaxy_triples(sample_clusters_dir))
        ts = set(triples)

        subj = "misp:77777777-7777-7777-7777-777777777777"
        assert (subj, "related-attack-id", "T1059.001") in ts

    def test_mitre_cluster_emits_relationships(self, sample_clusters_dir):
        triples = list(extract_misp_galaxy_triples(sample_clusters_dir))
        ts = set(triples)

        subj = "misp:77777777-7777-7777-7777-777777777777"
        assert (subj, "subtechnique-of", "misp:88888888-8888-8888-8888-888888888888") in ts

    def test_attack_id_in_synonyms(self, sample_clusters_dir):
        triples = list(extract_misp_galaxy_triples(sample_clusters_dir))
        ts = set(triples)

        subj = "misp:11111111-1111-1111-1111-111111111111"
        # G0006 in synonyms should create a cross-link
        assert (subj, "related-attack-id", "G0006") in ts

    def test_skipped_clusters(self, sample_clusters_dir):
        triples = list(extract_misp_galaxy_triples(sample_clusters_dir))
        subjects = {s for s, _, _ in triples}

        # cancer.json entry should not appear
        assert "misp:99999999-9999-9999-9999-999999999999" not in subjects

    def test_no_uuid_skipped(self, sample_clusters_dir):
        triples = list(extract_misp_galaxy_triples(sample_clusters_dir))
        # The entry "NoUUID Actor" has no uuid, should produce no triples
        names = [o for _, p, o in triples if p == "name"]
        assert "NoUUID Actor" not in names

    def test_refs_not_emitted(self, sample_clusters_dir):
        """Reference URLs should not be emitted as triples (avoids bloat)."""
        triples = list(extract_misp_galaxy_triples(sample_clusters_dir))
        predicates = {p for _, p, _ in triples}
        assert "refs" not in predicates

    def test_triple_count(self, sample_clusters_dir):
        triples = list(extract_misp_galaxy_triples(sample_clusters_dir))
        # APT1: ~17 triples, WannaCry: ~6 triples, MITRE entry: ~3 triples
        assert len(triples) > 15
        assert len(triples) < 50
