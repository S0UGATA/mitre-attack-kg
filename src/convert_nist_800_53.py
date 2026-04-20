"""NIST 800-53 ATT&CK Mappings (Mappings Explorer) JSON -> Knowledge Graph SPO Triples."""

import json
import logging
from collections.abc import Iterator
from pathlib import Path

from common import SOURCE_DIR, Triple, download_github_zip, make_triple_fn, meta_json

logger = logging.getLogger(__name__)

SOURCE = "nist_800_53"


_t = make_triple_fn(SOURCE)


def download_nist_800_53(cache_dir: str | None = None, *, force_download: bool = False) -> str:
    cache = Path(cache_dir) if cache_dir else SOURCE_DIR
    path = download_github_zip(
        "center-for-threat-informed-defense",
        "mappings-explorer",
        "mappings_explorer.zip",
        "main",
        cache,
        force_download=force_download,
    )
    return str(path)


def _find_mapping_file(repo_path: Path) -> Path | None:
    """Auto-detect the latest NIST 800-53 rev5 enterprise mapping JSON."""
    base = repo_path / "mappings" / "nist_800_53"
    if not base.exists():
        return None

    attack_dirs = sorted(
        [d for d in base.iterdir() if d.is_dir() and d.name.startswith("attack-")],
        reverse=True,
    )
    for attack_dir in attack_dirs:
        enterprise_dir = attack_dir / "nist_800_53-rev5" / "enterprise"
        if enterprise_dir.exists():
            json_files = list(enterprise_dir.glob("*.json"))
            if json_files:
                return json_files[0]
    return None


def extract_nist_800_53_triples(
    repo_dir: str,
) -> Iterator[Triple]:
    repo_path = Path(repo_dir)

    mapping_file = _find_mapping_file(repo_path)
    if not mapping_file:
        logger.warning("NIST 800-53 mapping JSON not found in %s", repo_path)
        return

    logger.info("Using mapping file: %s", mapping_file)

    with open(mapping_file) as f:
        data = json.load(f)

    mapping_objects = data.get("mapping_objects", [])
    logger.info("Found %d mapping objects", len(mapping_objects))

    emitted_controls: set[str] = set()

    for obj in mapping_objects:
        capability_id = obj.get("capability_id", "")
        if not capability_id:
            continue

        attack_id = obj.get("attack_object_id", "")
        if not attack_id:
            continue

        eid = str(capability_id)

        if eid not in emitted_controls:
            emitted_controls.add(eid)
            yield _t(eid, "rdf:type", "SecurityControl")
            yield _t(eid, "name", capability_id)

            desc = obj.get("capability_description", "")
            if desc:
                yield _t(eid, "description", str(desc))

            family = capability_id.split("-", 1)[0]
            yield _t(eid, "control-family", family)

        mapping_meta: dict = {}
        score_cat = obj.get("score_category", "")
        if score_cat:
            mapping_meta["score_category"] = score_cat
        score_val = obj.get("score_value", "")
        if score_val:
            mapping_meta["score_value"] = score_val

        yield _t(eid, "mitigates-technique", attack_id, meta_json(mapping_meta))


if __name__ == "__main__":
    import argparse

    from common import write_triples_streaming

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description="NIST 800-53 -> KG Triples (Parquet)")
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument("--cache-dir", type=str, default=None)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    path = download_nist_800_53(args.cache_dir)
    write_triples_streaming(
        extract_nist_800_53_triples(path), args.output_dir / "nist_800_53.parquet"
    )
