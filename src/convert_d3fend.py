"""MITRE D3FEND JSON-LD → Knowledge Graph SPO Triples."""

import json
import logging
from pathlib import Path

from common import download_file, get_object_type, meta_json

logger = logging.getLogger(__name__)

SOURCE = "d3fend"

D3FEND_URL = "https://d3fend.mitre.org/ontologies/d3fend.json"


def download_d3fend(cache_dir: str | None = None) -> str:
    """Download D3FEND JSON-LD, returning the local file path."""
    return str(download_file(D3FEND_URL, "d3fend.json", cache_dir))


def _t(s: str, p: str, o: str, m: str = "") -> tuple[str, str, str, str, str, str]:
    return (s, p, o, SOURCE, get_object_type(p), m)


def _extract_subclass_ids(node: dict) -> list[str]:
    """Extract rdfs:subClassOf IDs (skip blank nodes)."""
    sub = node.get("rdfs:subClassOf", [])
    if isinstance(sub, dict):
        sub = [sub]
    return [
        s["@id"].replace("d3f:", "")
        for s in sub
        if isinstance(s, dict) and "@id" in s and not s["@id"].startswith("_:")
    ]


def extract_d3fend_triples(json_path: str) -> list[tuple[str, str, str, str, str, str]]:
    """Extract SPO triples from D3FEND JSON-LD ontology."""
    with open(json_path) as f:
        data = json.load(f)

    graph = data.get("@graph", [])
    triples: list[tuple[str, str, str, str, str, str]] = []
    attack_ids: set[str] = set()
    deferred_refs: list[tuple[str, str, str]] = []

    _SKIP_KEYS = frozenset(
        {
            "d3f:d3fend-id",
            "d3f:definition",
            "d3f:synonym",
            "d3f:kb-reference",
            "d3f:kb-article",
        }
    )

    for node in graph:
        node_id = node.get("@id", "")
        if not node_id.startswith("d3f:"):
            continue

        d3fend_id = node.get("d3f:d3fend-id")
        attack_id = node.get("d3f:attack-id")

        if d3fend_id:
            sid = d3fend_id
            # Entity-level meta: kb references
            entity_meta: dict = {}
            kb_refs = node.get("d3f:kb-reference", [])
            if isinstance(kb_refs, str):
                kb_refs = [kb_refs]
            elif isinstance(kb_refs, dict):
                kb_refs = [kb_refs.get("@id", "")] if "@id" in kb_refs else []
            kb_urls = [r for r in kb_refs if isinstance(r, str) and r]
            if kb_urls:
                entity_meta["kb_references"] = kb_urls

            triples.append(_t(sid, "rdf:type", "DefensiveTechnique", meta_json(entity_meta)))

            label = node.get("rdfs:label")
            if isinstance(label, str) and label:
                triples.append(_t(sid, "name", label))

            definition = node.get("d3f:definition")
            if isinstance(definition, str) and definition:
                triples.append(_t(sid, "definition", definition))

            synonyms = node.get("d3f:synonym", [])
            if isinstance(synonyms, str):
                synonyms = [synonyms]
            for syn in synonyms:
                if syn:
                    triples.append(_t(sid, "synonym", syn))

            for parent_id in _extract_subclass_ids(node):
                triples.append(_t(sid, "child-of", parent_id))

            for key, val in node.items():
                if not key.startswith("d3f:") or key in _SKIP_KEYS:
                    continue
                refs = val if isinstance(val, list) else [val]
                for ref in refs:
                    if isinstance(ref, dict) and "@id" in ref:
                        ref_id = ref["@id"].replace("d3f:", "")
                        deferred_refs.append((d3fend_id, key.replace("d3f:", ""), ref_id))

        elif attack_id:
            sid = attack_id
            attack_ids.add(attack_id)
            triples.append(_t(sid, "rdf:type", "OffensiveTechnique"))

            label = node.get("rdfs:label")
            if isinstance(label, str) and label:
                triples.append(_t(sid, "d3fend-name", label))

            definition = node.get("d3f:definition")
            if isinstance(definition, str) and definition:
                triples.append(_t(sid, "d3fend-definition", definition))

            for parent_id in _extract_subclass_ids(node):
                triples.append(_t(sid, "child-of", parent_id))

    for d3fend_id, predicate, ref_id in deferred_refs:
        if ref_id in attack_ids:
            triples.append(_t(d3fend_id, predicate, ref_id))

    return triples


if __name__ == "__main__":
    import argparse

    from common import triples_to_dataframe, write_parquet

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description="D3FEND → KG Triples (Parquet)")
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument("--cache-dir", type=str, default=None)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    path = download_d3fend(args.cache_dir)
    df = triples_to_dataframe(extract_d3fend_triples(path))
    write_parquet(df, args.output_dir / "d3fend.parquet")
