"""Tests for convert_nuclei.py — Nuclei Templates YAML -> SPO triples converter."""

import pytest
import yaml

from convert_nuclei import extract_nuclei_triples

SAMPLE_CVE_TEMPLATE = {
    "id": "CVE-2024-21887",
    "info": {
        "name": "Ivanti Connect Secure - Command Injection",
        "severity": "critical",
        "author": ["researcher1", "researcher2"],
        "description": "Command injection vulnerability in Ivanti Connect Secure.",
        "tags": ["cve-2024-21887", "cwe-77", "ivanti"],
        "classification": {
            "cve-id": ["CVE-2024-21887"],
            "cwe-id": ["CWE-77"],
            "cvss-score": 9.1,
            "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
        },
    },
}

SAMPLE_NON_CVE_TEMPLATE = {
    "id": "wordpress-starter-templates-xss",
    "info": {
        "name": "WordPress Starter Templates XSS",
        "severity": "medium",
        "author": "tester",
        "description": "Cross-site scripting in WordPress Starter Templates plugin.",
        "tags": ["xss", "wordpress", "cve-2023-12345", "cwe-79"],
        "classification": {
            "cve-id": ["CVE-2023-12345"],
            "cwe-id": ["CWE-79"],
        },
    },
}

SAMPLE_MINIMAL_TEMPLATE = {
    "id": "tech-detect-nginx",
    "info": {
        "name": "Nginx Detection",
        "severity": "info",
        "author": "someone",
    },
}

SAMPLE_NO_ID = {
    "info": {
        "name": "Template Without ID",
    },
}

SAMPLE_NO_INFO = {
    "id": "broken-template",
}


@pytest.fixture
def sample_dir(tmp_path):
    templates = tmp_path / "http" / "cves" / "2024"
    templates.mkdir(parents=True)
    (templates / "CVE-2024-21887.yaml").write_text(yaml.dump(SAMPLE_CVE_TEMPLATE))

    misc = tmp_path / "http" / "miscellaneous"
    misc.mkdir(parents=True)
    (misc / "wordpress-xss.yaml").write_text(yaml.dump(SAMPLE_NON_CVE_TEMPLATE))

    tech = tmp_path / "http" / "technologies"
    tech.mkdir(parents=True)
    (tech / "nginx.yaml").write_text(yaml.dump(SAMPLE_MINIMAL_TEMPLATE))
    (tech / "noid.yaml").write_text(yaml.dump(SAMPLE_NO_ID))
    (tech / "noinfo.yaml").write_text(yaml.dump(SAMPLE_NO_INFO))

    return str(tmp_path)


class TestNucleiTriples:
    def test_cve_template_properties(self, sample_dir):
        triples = list(extract_nuclei_triples(sample_dir))
        ts = {t[:3] for t in triples}

        assert ("CVE-2024-21887", "rdf:type", "NucleiTemplate") in ts
        assert ("CVE-2024-21887", "name", "Ivanti Connect Secure - Command Injection") in ts
        assert ("CVE-2024-21887", "severity", "critical") in ts

    def test_cve_template_no_self_link(self, sample_dir):
        triples = list(extract_nuclei_triples(sample_dir))
        cve_links = [t for t in triples if t[0] == "CVE-2024-21887" and t[1] == "related-cve"]
        assert len(cve_links) == 0

    def test_cve_template_weakness(self, sample_dir):
        triples = list(extract_nuclei_triples(sample_dir))
        ts = {t[:3] for t in triples}

        assert ("CVE-2024-21887", "related-weakness", "CWE-77") in ts

    def test_cve_template_cvss(self, sample_dir):
        triples = list(extract_nuclei_triples(sample_dir))
        ts = {t[:3] for t in triples}

        assert ("CVE-2024-21887", "cvss-base-score", "9.1") in ts
        cvss = "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H"
        assert ("CVE-2024-21887", "cvss-vector", cvss) in ts

    def test_cve_template_author_list(self, sample_dir):
        triples = list(extract_nuclei_triples(sample_dir))
        author_triples = [t for t in triples if t[0] == "CVE-2024-21887" and t[1] == "author"]
        assert len(author_triples) == 1
        assert "researcher1" in author_triples[0][2]
        assert "researcher2" in author_triples[0][2]

    def test_non_cve_template_cross_links(self, sample_dir):
        triples = list(extract_nuclei_triples(sample_dir))
        ts = {t[:3] for t in triples}
        eid = "wordpress-starter-templates-xss"

        assert (eid, "rdf:type", "NucleiTemplate") in ts
        assert (eid, "related-cve", "CVE-2023-12345") in ts
        assert (eid, "related-weakness", "CWE-79") in ts

    def test_minimal_template(self, sample_dir):
        triples = list(extract_nuclei_triples(sample_dir))
        ts = {t[:3] for t in triples}

        assert ("tech-detect-nginx", "rdf:type", "NucleiTemplate") in ts
        assert ("tech-detect-nginx", "name", "Nginx Detection") in ts
        assert ("tech-detect-nginx", "severity", "info") in ts

    def test_no_id_skipped(self, sample_dir):
        triples = list(extract_nuclei_triples(sample_dir))
        subjects = {t[0] for t in triples}
        assert "" not in subjects

    def test_no_info_skipped(self, sample_dir):
        triples = list(extract_nuclei_triples(sample_dir))
        subjects = {t[0] for t in triples}
        assert "broken-template" not in subjects

    def test_no_duplicate_cwe_cve_triples(self, sample_dir):
        triples = list(extract_nuclei_triples(sample_dir))
        cwe_triples = [
            t[:3] for t in triples if t[0] == "CVE-2024-21887" and t[1] == "related-weakness"
        ]
        assert cwe_triples == [("CVE-2024-21887", "related-weakness", "CWE-77")]

        eid = "wordpress-starter-templates-xss"
        cve_triples = [t[:3] for t in triples if t[0] == eid and t[1] == "related-cve"]
        assert cve_triples == [(eid, "related-cve", "CVE-2023-12345")]
        cwe_triples2 = [t[:3] for t in triples if t[0] == eid and t[1] == "related-weakness"]
        assert cwe_triples2 == [(eid, "related-weakness", "CWE-79")]

    def test_triple_count(self, sample_dir):
        triples = list(extract_nuclei_triples(sample_dir))
        assert len(triples) > 10
        assert len(triples) < 100
