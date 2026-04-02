"""MITRE ATT&CK STIX → Knowledge Graph SPO Triples."""

import logging
from pathlib import Path

import pandas as pd
from mitreattack.stix20 import MitreAttackData

from common import download_file, triples_to_dataframe, write_parquet

logger = logging.getLogger(__name__)

STIX_BASE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"

DOMAINS = {
    "enterprise": f"{STIX_BASE_URL}/enterprise-attack/enterprise-attack.json",
    "mobile": f"{STIX_BASE_URL}/mobile-attack/mobile-attack.json",
    "ics": f"{STIX_BASE_URL}/ics-attack/ics-attack.json",
}

# STIX type -> human-readable ATT&CK concept
STIX_TYPE_LABELS = {
    "attack-pattern": "Technique",
    "x-mitre-tactic": "Tactic",
    "intrusion-set": "Group",
    "malware": "Malware",
    "tool": "Tool",
    "course-of-action": "Mitigation",
    "campaign": "Campaign",
    "x-mitre-data-source": "DataSource",
    "x-mitre-data-component": "DataComponent",
    "x-mitre-asset": "Asset",
}

# Entity types and the getter method name on MitreAttackData
ENTITY_GETTERS = {
    "Technique": "get_techniques",
    "Tactic": "get_tactics",
    "Group": "get_groups",
    "Software": "get_software",
    "Mitigation": "get_mitigations",
    "Campaign": "get_campaigns",
    "DataSource": "get_datasources",
    "DataComponent": "get_datacomponents",
}


def download_stix(domain: str, cache_dir: str | None = None) -> str:
    """Download a STIX JSON bundle, returning the local file path."""
    url = DOMAINS[domain]
    path = download_file(url, f"{domain}-attack.json", cache_dir)
    return str(path)


def _resolve_id(attack: MitreAttackData, stix_id: str) -> str:
    """Resolve a STIX UUID to its ATT&CK ID (e.g. T1059.001). Falls back to STIX ID."""
    attack_id = attack.get_attack_id(stix_id)
    return attack_id if attack_id else stix_id


def _extract_url(obj) -> str | None:
    """Return the ATT&CK URL from external_references, or None."""
    for ref in getattr(obj, "external_references", []):
        if hasattr(ref, "url") and "attack.mitre.org" in ref.url:
            return ref.url
    return None


def _extract_tactic_ids(
    obj,
    tactic_map: dict[str, str] | None,
) -> list[str]:
    """Return tactic IDs from kill_chain_phases."""
    ids = []
    for phase in getattr(obj, "kill_chain_phases", []):
        if phase.kill_chain_name == "mitre-attack":
            tactic_id = (
                tactic_map.get(phase.phase_name, phase.phase_name)
                if tactic_map
                else phase.phase_name
            )
            ids.append(tactic_id)
    return ids


def _list_attr_triples(sid: str, obj, attr: str, predicate: str) -> list[tuple[str, str, str]]:
    """Produce one triple per item in a list attribute, if it exists."""
    return [(sid, predicate, val) for val in getattr(obj, attr, [])]


def _entity_triples(
    attack: MitreAttackData,
    obj,
    label: str,
    tactic_map: dict[str, str] | None = None,
) -> list[tuple[str, str, str]]:
    """Extract property triples from a single STIX entity object."""
    sid = _resolve_id(attack, obj.id)

    triples = [
        (sid, "rdf:type", label),
        (sid, "name", obj.name),
        (sid, "created", str(obj.created)),
        (sid, "modified", str(obj.modified)),
    ]

    if getattr(obj, "description", None):
        triples.append((sid, "description", obj.description))

    triples.extend(_list_attr_triples(sid, obj, "x_mitre_platforms", "platform"))
    triples.extend(_list_attr_triples(sid, obj, "x_mitre_domains", "domain"))

    for alias in getattr(obj, "aliases", []):
        if alias != obj.name:
            triples.append((sid, "alias", alias))

    if hasattr(obj, "x_mitre_is_subtechnique"):
        triples.append((sid, "is-subtechnique", str(obj.x_mitre_is_subtechnique)))

    if getattr(obj, "revoked", False):
        triples.append((sid, "revoked", "true"))

    if getattr(obj, "x_mitre_deprecated", False):
        triples.append((sid, "deprecated", "true"))

    url = _extract_url(obj)
    if url:
        triples.append((sid, "url", url))

    for tactic_id in _extract_tactic_ids(obj, tactic_map):
        triples.append((sid, "belongs-to-tactic", tactic_id))

    if hasattr(obj, "x_mitre_shortname"):
        triples.append((sid, "shortname", obj.x_mitre_shortname))

    return triples


def _build_tactic_map(attack: MitreAttackData, tactics: list) -> dict[str, str]:
    """Build a mapping from tactic shortname to ATT&CK ID."""
    return {
        tactic.x_mitre_shortname: _resolve_id(attack, tactic.id)
        for tactic in tactics
        if hasattr(tactic, "x_mitre_shortname")
    }


def _all_entity_triples(
    attack: MitreAttackData, tactics: list, tactic_map: dict[str, str]
) -> list[tuple[str, str, str]]:
    """Extract property triples for all entity types."""
    triples: list[tuple[str, str, str]] = []

    for label, getter_name in ENTITY_GETTERS.items():
        getter = getattr(attack, getter_name)
        if label == "Software":
            for obj in getter():
                sw_label = STIX_TYPE_LABELS.get(obj.type, "Software")
                triples.extend(_entity_triples(attack, obj, sw_label, tactic_map))
        else:
            for obj in tactics if label == "Tactic" else getter():
                triples.extend(_entity_triples(attack, obj, label, tactic_map))

    return triples


def _all_relationship_triples(attack: MitreAttackData) -> list[tuple[str, str, str]]:
    """Extract relationship triples from all STIX relationship objects."""
    return [
        (
            _resolve_id(attack, rel.source_ref),
            rel.relationship_type,
            _resolve_id(attack, rel.target_ref),
        )
        for rel in attack.get_objects_by_type("relationship")
    ]


def extract_triples(attack: MitreAttackData) -> list[tuple[str, str, str]]:
    """Extract all SPO triples from a loaded MitreAttackData instance."""
    tactics = attack.get_tactics()
    tactic_map = _build_tactic_map(attack, tactics)

    triples = _all_entity_triples(attack, tactics, tactic_map)
    triples.extend(_all_relationship_triples(attack))
    return triples


def convert_domain(
    domain: str, output_dir: Path, cache_dir: str | None = None, parquet_format: str = "v2"
) -> "pd.DataFrame":
    """Download STIX data for a domain, convert to triples, save as Parquet."""
    stix_path = download_stix(domain, cache_dir)
    logger.info("Loading %s into MitreAttackData ...", domain)
    attack = MitreAttackData(stix_path)
    logger.info("Extracting triples for %s ...", domain)
    triples = extract_triples(attack)
    df = triples_to_dataframe(triples)
    write_parquet(df, output_dir / f"{domain}.parquet", parquet_format)
    return df


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description="ATT&CK STIX → KG Triples (Parquet)")
    parser.add_argument(
        "--domains",
        nargs="+",
        default=list(DOMAINS.keys()),
        choices=list(DOMAINS.keys()),
    )
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument("--cache-dir", type=str, default=None)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for domain in args.domains:
        convert_domain(domain, args.output_dir, args.cache_dir)
