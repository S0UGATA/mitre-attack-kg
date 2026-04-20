"""EUVD (EU Vulnerability Database) JSON -> Knowledge Graph SPO Triples."""

import json
import logging
from collections.abc import Iterator
from pathlib import Path

from common import SOURCE_DIR, Triple, download_file, make_triple_fn, meta_json, truncate_text

logger = logging.getLogger(__name__)

SOURCE = "euvd"

EUVD_KEV_URL = "https://euvdservices.enisa.europa.eu/api/kev/dump"


_t = make_triple_fn(SOURCE)


def download_euvd(cache_dir: str | None = None, *, force_download: bool = False) -> str:
    cache = Path(cache_dir) if cache_dir else SOURCE_DIR
    path = download_file(EUVD_KEV_URL, "euvd_dump.json", cache, force_download=force_download)
    return str(path)


def _vuln_triples(record: dict) -> list[Triple]:
    euvd_id = record.get("euvdId", "")
    if not euvd_id:
        return []

    eid = str(euvd_id)
    triples: list[Triple] = [
        _t(eid, "rdf:type", "EUVulnerability"),
    ]

    desc = record.get("description")
    if desc:
        text = truncate_text(str(desc))
        triples.append(_t(eid, "description", text))

    date_pub = record.get("datePublished")
    if date_pub:
        triples.append(_t(eid, "date-published", str(date_pub)))

    base_score = record.get("baseScore")
    if base_score is not None:
        score_meta: dict = {}
        version = record.get("baseScoreVersion")
        if version:
            score_meta["cvss_version"] = str(version)
        triples.append(_t(eid, "cvss-base-score", str(base_score), meta_json(score_meta)))

    vector = record.get("baseScoreVector")
    if vector:
        triples.append(_t(eid, "cvss-vector", str(vector)))

    epss = record.get("epss")
    if epss is not None:
        triples.append(_t(eid, "epss-score", str(epss)))

    aliases = record.get("aliases", "")
    if aliases:
        for alias in str(aliases).split("\n"):
            alias = alias.strip().upper()
            if alias.startswith("CVE-"):
                triples.append(_t(eid, "related-cve", alias))

    for product_entry in record.get("productList", []):
        if not isinstance(product_entry, dict):
            continue
        vendor = product_entry.get("vendor")
        if vendor:
            triples.append(_t(eid, "vendor", str(vendor)))
        product = product_entry.get("product")
        if product:
            triples.append(_t(eid, "product", str(product)))

    return triples


def extract_euvd_triples(
    data_path: str,
) -> Iterator[Triple]:
    path = Path(data_path)
    logger.info("Reading EUVD data from %s", path)

    with open(path) as f:
        data = json.load(f)

    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        records = data.get("vulnerabilities", data.get("items", [data]))
    else:
        logger.warning("Unexpected EUVD data format")
        return

    logger.info("Found %d EUVD vulnerability records", len(records))

    for record in records:
        if isinstance(record, dict):
            yield from _vuln_triples(record)


if __name__ == "__main__":
    import argparse

    from common import write_triples_streaming

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description="EUVD -> KG Triples (Parquet)")
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument("--cache-dir", type=str, default=None)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    path = download_euvd(args.cache_dir)
    write_triples_streaming(extract_euvd_triples(path), args.output_dir / "euvd.parquet")
