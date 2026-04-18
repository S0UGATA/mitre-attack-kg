"""FIRST EPSS (Exploit Prediction Scoring System) CSV → Knowledge Graph SPO Triples."""

import csv
import gzip
import logging
from collections.abc import Iterator
from pathlib import Path

from common import download_file, get_object_type

logger = logging.getLogger(__name__)

SOURCE = "epss"


def _t(s: str, p: str, o: str, m: str = "") -> tuple[str, str, str, str, str, str]:
    return (s, p, o, SOURCE, get_object_type(p), m)


EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


def download_epss(cache_dir: str | None = None) -> str:
    """Download EPSS CSV (gzip), returning the local file path of the .gz file."""
    return str(download_file(EPSS_URL, "epss_scores-current.csv.gz", cache_dir))


def extract_epss_triples(gz_path: str) -> Iterator[tuple[str, str, str, str, str, str]]:
    """Yield SPO triples from EPSS gzipped CSV.

    The CSV has a comment line (starting with #) followed by:
    cve,epss,percentile
    CVE-2024-1234,0.00036,0.12345
    """
    with gzip.open(gz_path, "rt") as f:
        # Skip comment lines (start with #)
        lines = (line for line in f if not line.startswith("#"))
        reader = csv.DictReader(lines)

        for row in reader:
            cve_id = row.get("cve", "").strip()
            if not cve_id:
                continue

            epss = row.get("epss", "").strip()
            percentile = row.get("percentile", "").strip()

            if epss:
                yield _t(cve_id, "epss-score", epss)
            if percentile:
                yield _t(cve_id, "epss-percentile", percentile)


if __name__ == "__main__":
    import argparse

    from common import write_triples_streaming

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description="EPSS → KG Triples (Parquet)")
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument("--cache-dir", type=str, default=None)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    path = download_epss(args.cache_dir)
    write_triples_streaming(extract_epss_triples(path), args.output_dir / "epss.parquet")
