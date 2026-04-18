"""Tests for convert_epss.py — FIRST EPSS CSV → SPO triples converter."""

import gzip

import pytest

from convert_epss import extract_epss_triples

SAMPLE_CSV = """\
#model_version:v2024.01.01,score_date:2024-01-15
cve,epss,percentile
CVE-2024-1234,0.00036,0.12345
CVE-2024-5678,0.97500,0.99900
CVE-2024-0001,0.00100,0.50000
"""


@pytest.fixture
def sample_gz_path(tmp_path):
    path = tmp_path / "epss_scores.csv.gz"
    with gzip.open(path, "wt") as f:
        f.write(SAMPLE_CSV)
    return str(path)


class TestEpssTriples:
    def test_basic_scores(self, sample_gz_path):
        triples = list(extract_epss_triples(sample_gz_path))
        ts = {t[:3] for t in triples}

        assert ("CVE-2024-1234", "epss-score", "0.00036") in ts
        assert ("CVE-2024-1234", "epss-percentile", "0.12345") in ts

    def test_high_score(self, sample_gz_path):
        triples = list(extract_epss_triples(sample_gz_path))
        ts = {t[:3] for t in triples}

        assert ("CVE-2024-5678", "epss-score", "0.97500") in ts
        assert ("CVE-2024-5678", "epss-percentile", "0.99900") in ts

    def test_all_cves_present(self, sample_gz_path):
        triples = list(extract_epss_triples(sample_gz_path))
        subjects = {t[0] for t in triples}

        assert "CVE-2024-1234" in subjects
        assert "CVE-2024-5678" in subjects
        assert "CVE-2024-0001" in subjects

    def test_comment_line_skipped(self, sample_gz_path):
        triples = list(extract_epss_triples(sample_gz_path))
        # Should have exactly 3 CVEs x 2 triples = 6
        assert len(triples) == 6

    def test_only_two_predicates(self, sample_gz_path):
        triples = list(extract_epss_triples(sample_gz_path))
        predicates = {t[1] for t in triples}
        assert predicates == {"epss-score", "epss-percentile"}

    def test_empty_csv(self, tmp_path):
        path = tmp_path / "empty.csv.gz"
        with gzip.open(path, "wt") as f:
            f.write("#comment\ncve,epss,percentile\n")
        triples = list(extract_epss_triples(str(path)))
        assert triples == []
