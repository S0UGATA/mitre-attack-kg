"""MITRE ENGAGE JSON → Knowledge Graph SPO Triples."""

import json
import logging
from pathlib import Path

from common import download_file

logger = logging.getLogger(__name__)

ENGAGE_URL = "https://raw.githubusercontent.com/mitre/engage/main/Data/json/attack_mapping.json"


def download_engage(cache_dir: str | None = None) -> str:
    """Download ENGAGE JSON, returning the local file path."""
    return str(download_file(ENGAGE_URL, "engage_attack_mapping.json", cache_dir))


def extract_engage_triples(json_path: str) -> list[tuple[str, str, str]]:
    """Extract SPO triples from MITRE ENGAGE JSON.

    The JSON is a flat array of objects with keys:
    attack_id, attack_technique, eav_id, eav, eac, eac_id
    """
    with open(json_path) as f:
        data = json.load(f)

    triples: list[tuple[str, str, str]] = []
    seen_eac: set[str] = set()
    seen_eav: set[str] = set()
    seen_rels: set[tuple[str, str, str]] = set()

    for entry in data:
        eac_id = entry.get("eac_id", "")
        eac_name = entry.get("eac", "")
        eav_id = entry.get("eav_id", "")
        eav_desc = entry.get("eav", "")
        attack_id = entry.get("attack_id", "")

        # Engagement Activity entity (deduplicate)
        if eac_id and eac_id not in seen_eac:
            seen_eac.add(eac_id)
            triples.append((eac_id, "rdf:type", "EngagementActivity"))
            if eac_name:
                triples.append((eac_id, "name", eac_name))

        # Adversary Vulnerability entity (deduplicate)
        if eav_id and eav_id not in seen_eav:
            seen_eav.add(eav_id)
            triples.append((eav_id, "rdf:type", "AdversaryVulnerability"))
            if eav_desc:
                triples.append((eav_id, "description", eav_desc))

        # Relationships (deduplicate)
        for rel in (
            (eac_id, "engages-technique", attack_id) if eac_id and attack_id else None,
            (eav_id, "exploits-vulnerability-of", attack_id) if eav_id and attack_id else None,
            (eac_id, "addresses-vulnerability", eav_id) if eac_id and eav_id else None,
        ):
            if rel and rel not in seen_rels:
                seen_rels.add(rel)
                triples.append(rel)

    return triples


if __name__ == "__main__":
    import argparse

    from common import triples_to_dataframe, write_parquet

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description="ENGAGE → KG Triples (Parquet)")
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument("--cache-dir", type=str, default=None)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    path = download_engage(args.cache_dir)
    df = triples_to_dataframe(extract_engage_triples(path))
    write_parquet(df, args.output_dir / "engage.parquet")
