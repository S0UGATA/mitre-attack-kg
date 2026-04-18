"""NVD CPE (Common Platform Enumeration) Dictionary → Knowledge Graph SPO Triples."""

import json
import logging
from collections.abc import Iterator
from pathlib import Path

from common import download_tar_gz, get_object_type, meta_json

logger = logging.getLogger(__name__)

SOURCE = "cpe"

CPE_URL = "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz"

# CPE part codes
PART_LABELS = {
    "a": "application",
    "o": "operating_system",
    "h": "hardware",
}


def download_cpe(cache_dir: str | None = None) -> str:
    """Download NVD CPE dictionary tar.gz, extract, and return path to extraction dir."""
    extract_dir = download_tar_gz(CPE_URL, "nvdcpe-2.0.tar.gz", cache_dir)
    return str(extract_dir)


def _parse_cpe_uri(cpe_name: str) -> dict[str, str]:
    """Parse a CPE 2.3 URI into components."""
    parts = cpe_name.split(":")
    if len(parts) < 5:
        return {}
    return {
        "part": PART_LABELS.get(parts[2], parts[2]),
        "vendor": parts[3] if parts[3] != "*" else "",
        "product": parts[4] if parts[4] != "*" else "",
        "version": parts[5] if len(parts) > 5 and parts[5] != "*" else "",
    }


def _t(s: str, p: str, o: str, m: str = "") -> tuple[str, str, str, str, str, str]:
    return (s, p, o, SOURCE, get_object_type(p), m)


def extract_cpe_triples(data_dir: str) -> Iterator[tuple[str, str, str, str, str, str]]:
    """Yield SPO triples from NVD CPE dictionary JSON files.

    Returns a generator to avoid loading millions of triples into memory.
    """
    data_path = Path(data_dir)

    # Find the JSON file(s) in the extracted directory
    json_files = list(data_path.rglob("*.json"))
    if not json_files:
        raise FileNotFoundError(f"No JSON files found in {data_dir}")

    for json_file in json_files:
        logger.info("Processing %s ...", json_file)
        with open(json_file) as f:
            data = json.load(f)

        products = data.get("products", [])
        logger.info("Found %d CPE entries", len(products))

        for i, item in enumerate(products):
            if i > 0 and i % 100_000 == 0:
                logger.info("  processed %d / %d CPEs", i, len(products))

            cpe = item.get("cpe", {})
            cpe_name = cpe.get("cpeName", "")
            if not cpe_name:
                continue

            if cpe.get("deprecated", False):
                continue

            # Entity-level meta: references
            entity_meta: dict = {}
            refs = cpe.get("refs", [])
            if refs:
                ref_urls = [r.get("ref") for r in refs if r.get("ref")]
                if ref_urls:
                    entity_meta["references"] = ref_urls

            yield _t(cpe_name, "rdf:type", "Platform", meta_json(entity_meta))

            # Parse and add components
            components = _parse_cpe_uri(cpe_name)
            if components.get("part"):
                yield _t(cpe_name, "part", components["part"])
            if components.get("vendor"):
                yield _t(cpe_name, "vendor", components["vendor"])
            if components.get("product"):
                yield _t(cpe_name, "product", components["product"])
            if components.get("version"):
                yield _t(cpe_name, "version", components["version"])

            # Title (English only)
            en_title = next(
                (
                    t["title"]
                    for t in cpe.get("titles", [])
                    if t.get("lang") == "en" and t.get("title")
                ),
                None,
            )
            if en_title:
                yield _t(cpe_name, "title", en_title)

            # Dates
            if cpe.get("created"):
                yield _t(cpe_name, "created", cpe["created"])
            if cpe.get("lastModified"):
                yield _t(cpe_name, "modified", cpe["lastModified"])


if __name__ == "__main__":
    import argparse

    from common import write_triples_streaming

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description="CPE → KG Triples (Parquet)")
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument("--cache-dir", type=str, default=None)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    path = download_cpe(args.cache_dir)
    write_triples_streaming(extract_cpe_triples(path), args.output_dir / "cpe.parquet")
