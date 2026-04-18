"""MITRE ATLAS YAML → Knowledge Graph SPO Triples."""

import logging
from pathlib import Path

import yaml

from common import download_file, get_object_type, meta_json

logger = logging.getLogger(__name__)

SOURCE = "atlas"

ATLAS_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml"


def download_atlas(cache_dir: str | None = None) -> str:
    """Download ATLAS YAML, returning the local file path."""
    return str(download_file(ATLAS_URL, "ATLAS.yaml", cache_dir))


def _t(s: str, p: str, o: str, m: str = "") -> tuple[str, str, str, str, str, str]:
    return (s, p, o, SOURCE, get_object_type(p), m)


def _tactic_triples(tactic: dict) -> list[tuple[str, str, str, str, str, str]]:
    """Extract triples from a single ATLAS tactic."""
    tid = tactic.get("id", "")
    if not tid:
        return []

    triples = [_t(tid, "rdf:type", "Tactic")]
    if tactic.get("name"):
        triples.append(_t(tid, "name", tactic["name"]))
    if tactic.get("description"):
        triples.append(_t(tid, "description", tactic["description"]))
    if tactic.get("created_date"):
        triples.append(_t(tid, "created", str(tactic["created_date"])))
    if tactic.get("modified_date"):
        triples.append(_t(tid, "modified", str(tactic["modified_date"])))

    attack_ref = tactic.get("ATT&CK-reference")
    if attack_ref and attack_ref.get("id"):
        triples.append(_t(tid, "related-attack-tactic", attack_ref["id"]))

    return triples


def _technique_triples(tech: dict) -> list[tuple[str, str, str, str, str, str]]:
    """Extract triples from a single ATLAS technique or subtechnique."""
    tid = tech.get("id", "")
    if not tid:
        return []

    triples = [_t(tid, "rdf:type", "Technique")]
    if tech.get("name"):
        triples.append(_t(tid, "name", tech["name"]))
    if tech.get("description"):
        triples.append(_t(tid, "description", tech["description"]))
    if tech.get("created_date"):
        triples.append(_t(tid, "created", str(tech["created_date"])))
    if tech.get("modified_date"):
        triples.append(_t(tid, "modified", str(tech["modified_date"])))
    if tech.get("maturity"):
        triples.append(_t(tid, "maturity", tech["maturity"]))

    for tactic_id in tech.get("tactics", []):
        triples.append(_t(tid, "belongs-to-tactic", tactic_id))

    if tech.get("subtechnique-of"):
        triples.append(_t(tid, "subtechnique-of", tech["subtechnique-of"]))

    attack_ref = tech.get("ATT&CK-reference")
    if attack_ref and attack_ref.get("id"):
        triples.append(_t(tid, "related-attack-technique", attack_ref["id"]))

    return triples


def _case_study_triples(case: dict) -> list[tuple[str, str, str, str, str, str]]:
    """Extract triples from a case study."""
    cid = case.get("id", "")
    if not cid:
        return []

    # Entity-level meta: references
    entity_meta: dict = {}
    refs = case.get("references", [])
    if refs:
        ref_entries = [r.get("url") or r for r in refs if isinstance(r, (str, dict))]
        ref_urls = [r for r in ref_entries if isinstance(r, str)]
        if ref_urls:
            entity_meta["references"] = ref_urls

    triples = [_t(cid, "rdf:type", "CaseStudy", meta_json(entity_meta))]
    if case.get("name"):
        triples.append(_t(cid, "name", case["name"]))
    if case.get("description"):
        triples.append(_t(cid, "description", case["description"]))

    for tech_id in case.get("techniques", []):
        triples.append(_t(cid, "uses-technique", tech_id))

    return triples


def _mitigation_triples(mit: dict) -> list[tuple[str, str, str, str, str, str]]:
    """Extract triples from a mitigation."""
    mid = mit.get("id", "")
    if not mid:
        return []

    triples = [_t(mid, "rdf:type", "Mitigation")]
    if mit.get("name"):
        triples.append(_t(mid, "name", mit["name"]))
    if mit.get("description"):
        triples.append(_t(mid, "description", mit["description"]))

    for tech_id in mit.get("techniques", []):
        triples.append(_t(mid, "mitigates", tech_id))

    return triples


def extract_atlas_triples(yaml_path: str) -> list[tuple[str, str, str, str, str, str]]:
    """Extract SPO triples from ATLAS YAML."""
    with open(yaml_path) as f:
        data = yaml.safe_load(f)

    triples: list[tuple[str, str, str, str, str, str]] = []

    for matrix in data.get("matrices", []):
        for tactic in matrix.get("tactics", []):
            triples.extend(_tactic_triples(tactic))
        for tech in matrix.get("techniques", []):
            triples.extend(_technique_triples(tech))

    for case in data.get("case-studies", data.get("case_studies", [])):
        triples.extend(_case_study_triples(case))

    for mit in data.get("mitigations", []):
        triples.extend(_mitigation_triples(mit))

    return triples


if __name__ == "__main__":
    import argparse

    from common import triples_to_dataframe, write_parquet

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description="ATLAS → KG Triples (Parquet)")
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument("--cache-dir", type=str, default=None)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    path = download_atlas(args.cache_dir)
    df = triples_to_dataframe(extract_atlas_triples(path))
    write_parquet(df, args.output_dir / "atlas.parquet")
