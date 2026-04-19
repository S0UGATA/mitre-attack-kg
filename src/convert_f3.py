"""MITRE F3 (Fight Fraud Framework) STIX 2.1 → Knowledge Graph SPO Triples."""

import json
import logging
from pathlib import Path

from common import download_file, get_object_type

logger = logging.getLogger(__name__)

SOURCE = "f3"

F3_URL = "https://raw.githubusercontent.com/center-for-threat-informed-defense/fight-fraud-framework/main/public/f3-stix.json"


def download_f3(cache_dir: str | None = None) -> str:
    """Download F3 STIX 2.1 bundle, returning the local file path."""
    return str(download_file(F3_URL, "f3-stix.json", cache_dir))


def _t(s: str, p: str, o: str, m: str = "") -> tuple[str, str, str, str, str, str]:
    return (s, p, o, SOURCE, get_object_type(p), m)


def _resolve_id(obj: dict) -> str:
    """Extract the F3/ATT&CK external ID from external_references, falling back to STIX ID."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-f3" and ref.get("external_id"):
            return ref["external_id"]
    return obj.get("id", "")


def _tactic_triples(tactic: dict) -> list[tuple[str, str, str, str, str, str]]:
    """Extract triples from an F3 tactic (x-mitre-tactic)."""
    tid = _resolve_id(tactic)
    if not tid:
        return []

    triples = [_t(tid, "rdf:type", "Tactic")]
    if tactic.get("name"):
        triples.append(_t(tid, "name", tactic["name"]))
    if tactic.get("description"):
        triples.append(_t(tid, "description", tactic["description"]))
    if tactic.get("created"):
        triples.append(_t(tid, "created", tactic["created"]))
    if tactic.get("modified"):
        triples.append(_t(tid, "modified", tactic["modified"]))
    if tactic.get("x_mitre_shortname"):
        triples.append(_t(tid, "shortname", tactic["x_mitre_shortname"]))

    return triples


def _technique_triples(
    tech: dict, tactic_lookup: dict[str, str]
) -> list[tuple[str, str, str, str, str, str]]:
    """Extract triples from an F3 technique (attack-pattern)."""
    tid = _resolve_id(tech)
    if not tid:
        return []

    triples = [_t(tid, "rdf:type", "Technique")]
    if tech.get("name"):
        triples.append(_t(tid, "name", tech["name"]))
    if tech.get("description"):
        triples.append(_t(tid, "description", tech["description"]))
    if tech.get("created"):
        triples.append(_t(tid, "created", tech["created"]))
    if tech.get("modified"):
        triples.append(_t(tid, "modified", tech["modified"]))
    if tech.get("x_mitre_is_subtechnique"):
        triples.append(_t(tid, "is-subtechnique", "true"))

    for phase in tech.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") == "mitre-f3":
            tactic_id = tactic_lookup.get(phase.get("phase_name", ""))
            if tactic_id:
                triples.append(_t(tid, "belongs-to-tactic", tactic_id))

    for ref in tech.get("external_references", []):
        if ref.get("source_name") == "mitre-f3" and ref.get("url"):
            triples.append(_t(tid, "url", ref["url"]))
            break

    return triples


def extract_f3_triples(json_path: str) -> list[tuple[str, str, str, str, str, str]]:
    """Extract SPO triples from F3 STIX 2.1 bundle."""
    with open(json_path) as f:
        bundle = json.load(f)

    objects = bundle.get("objects", [])

    stix_to_ext: dict[str, str] = {}
    tactic_shortname_to_id: dict[str, str] = {}
    tactics: list[dict] = []
    techniques: list[dict] = []
    relationships: list[dict] = []

    for obj in objects:
        obj_type = obj.get("type", "")
        if obj_type == "x-mitre-tactic":
            ext_id = _resolve_id(obj)
            stix_to_ext[obj["id"]] = ext_id
            if obj.get("x_mitre_shortname"):
                tactic_shortname_to_id[obj["x_mitre_shortname"]] = ext_id
            tactics.append(obj)
        elif obj_type == "attack-pattern":
            stix_to_ext[obj["id"]] = _resolve_id(obj)
            techniques.append(obj)
        elif obj_type == "relationship":
            relationships.append(obj)

    triples: list[tuple[str, str, str, str, str, str]] = []

    for tactic in tactics:
        triples.extend(_tactic_triples(tactic))

    for tech in techniques:
        triples.extend(_technique_triples(tech, tactic_shortname_to_id))

    for rel in relationships:
        if rel.get("relationship_type") == "subtechnique-of":
            source_id = stix_to_ext.get(rel.get("source_ref", ""))
            target_id = stix_to_ext.get(rel.get("target_ref", ""))
            if source_id and target_id:
                triples.append(_t(source_id, "subtechnique-of", target_id))

    logger.info(
        "Extracted %d triples from F3 (%d tactics, %d techniques, %d relationships)",
        len(triples),
        len(tactics),
        len(techniques),
        len(relationships),
    )

    return triples


if __name__ == "__main__":
    import argparse

    from common import triples_to_dataframe, write_parquet

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description="F3 → KG Triples (Parquet)")
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument("--cache-dir", type=str, default=None)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    path = download_f3(args.cache_dir)
    df = triples_to_dataframe(extract_f3_triples(path))
    write_parquet(df, args.output_dir / "f3.parquet")
