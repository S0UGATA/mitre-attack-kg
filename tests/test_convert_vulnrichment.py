"""Tests for convert_vulnrichment.py — CISA Vulnrichment JSON → SPO triples converter."""

import json

import pytest

from convert_vulnrichment import extract_vulnrichment_triples

SAMPLE_CVE_1 = {
    "cveMetadata": {
        "cveId": "CVE-2024-1234",
        "state": "PUBLISHED",
    },
    "containers": {
        "cna": {},
        "adp": [
            {
                "providerMetadata": {
                    "orgId": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                    "shortName": "CISA-ADP",
                },
                "metrics": [
                    {
                        "cvssV3_1": {
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        },
                        "other": {
                            "type": "ssvc",
                            "content": {
                                "id": "CVE-2024-1234",
                                "options": [
                                    {"Exploitation": "active"},
                                    {"Automatable": "yes"},
                                    {"Technical Impact": "total"},
                                ],
                                "role": "CISA Coordinator",
                                "version": "2.0.3",
                            },
                        },
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "cweId": "CWE-79",
                                "description": "Cross-site Scripting",
                                "lang": "en",
                                "type": "CWE",
                            }
                        ]
                    }
                ],
                "affected": [
                    {
                        "vendor": "Microsoft",
                        "product": "Windows",
                        "cpes": ["cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*"],
                    }
                ],
            }
        ],
    },
}

SAMPLE_CVE_2 = {
    "cveMetadata": {
        "cveId": "CVE-2024-5678",
        "state": "PUBLISHED",
    },
    "containers": {
        "cna": {},
        "adp": [
            {
                "providerMetadata": {"shortName": "CISA-ADP"},
                "metrics": [
                    {
                        "other": {
                            "type": "ssvc",
                            "content": {
                                "options": [
                                    {"Exploitation": "none"},
                                    {"Automatable": "no"},
                                    {"Technical Impact": "partial"},
                                ],
                            },
                        },
                    }
                ],
            }
        ],
    },
}

SAMPLE_CVE_REJECTED = {
    "cveMetadata": {
        "cveId": "CVE-2024-9999",
        "state": "REJECTED",
    },
    "containers": {},
}

SAMPLE_CVE_NO_ADP = {
    "cveMetadata": {
        "cveId": "CVE-2024-0001",
        "state": "PUBLISHED",
    },
    "containers": {"cna": {}},
}


@pytest.fixture
def sample_cve_dir(tmp_path):
    d = tmp_path / "2024" / "1xxx"
    d.mkdir(parents=True)
    (d / "CVE-2024-1234.json").write_text(json.dumps(SAMPLE_CVE_1))

    d2 = tmp_path / "2024" / "5xxx"
    d2.mkdir(parents=True)
    (d2 / "CVE-2024-5678.json").write_text(json.dumps(SAMPLE_CVE_2))

    d3 = tmp_path / "2024" / "9xxx"
    d3.mkdir(parents=True)
    (d3 / "CVE-2024-9999.json").write_text(json.dumps(SAMPLE_CVE_REJECTED))

    d4 = tmp_path / "2024" / "0xxx"
    d4.mkdir(parents=True)
    (d4 / "CVE-2024-0001.json").write_text(json.dumps(SAMPLE_CVE_NO_ADP))

    return str(tmp_path)


class TestVulnrichmentTriples:
    def test_cvss_scores(self, sample_cve_dir):
        triples = list(extract_vulnrichment_triples(sample_cve_dir))
        ts = set(triples)

        assert ("CVE-2024-1234", "adp-cvss-base-score", "9.8") in ts
        assert ("CVE-2024-1234", "adp-cvss-severity", "CRITICAL") in ts

    def test_ssvc_decision_points(self, sample_cve_dir):
        triples = list(extract_vulnrichment_triples(sample_cve_dir))
        ts = set(triples)

        assert ("CVE-2024-1234", "ssvc-exploitation", "active") in ts
        assert ("CVE-2024-1234", "ssvc-automatable", "yes") in ts
        assert ("CVE-2024-1234", "ssvc-technical-impact", "total") in ts

    def test_cwe_from_adp(self, sample_cve_dir):
        triples = list(extract_vulnrichment_triples(sample_cve_dir))
        ts = set(triples)

        assert ("CVE-2024-1234", "adp-related-weakness", "CWE-79") in ts

    def test_cpe_from_adp(self, sample_cve_dir):
        triples = list(extract_vulnrichment_triples(sample_cve_dir))
        ts = set(triples)

        assert (
            "CVE-2024-1234",
            "adp-affects-cpe",
            "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*",
        ) in ts

    def test_second_cve_ssvc(self, sample_cve_dir):
        triples = list(extract_vulnrichment_triples(sample_cve_dir))
        ts = set(triples)

        assert ("CVE-2024-5678", "ssvc-exploitation", "none") in ts
        assert ("CVE-2024-5678", "ssvc-automatable", "no") in ts
        assert ("CVE-2024-5678", "ssvc-technical-impact", "partial") in ts

    def test_rejected_skipped(self, sample_cve_dir):
        triples = list(extract_vulnrichment_triples(sample_cve_dir))
        subjects = {s for s, _, _ in triples}

        assert "CVE-2024-9999" not in subjects

    def test_no_adp_produces_no_triples(self, sample_cve_dir):
        triples = list(extract_vulnrichment_triples(sample_cve_dir))
        subjects = {s for s, _, _ in triples}

        # CVE-2024-0001 has no ADP container, so no enrichment triples
        assert "CVE-2024-0001" not in subjects

    def test_triple_count(self, sample_cve_dir):
        triples = list(extract_vulnrichment_triples(sample_cve_dir))
        assert len(triples) > 5
        assert len(triples) < 50
