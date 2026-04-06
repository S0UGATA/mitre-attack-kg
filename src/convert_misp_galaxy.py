"""MISP Galaxy Clusters JSON → Knowledge Graph SPO Triples."""

import json
import logging
import re
from pathlib import Path

from common import download_github_zip

logger = logging.getLogger(__name__)

# Clusters to skip (not security-relevant)
SKIP_CLUSTERS = frozenset(
    {
        "ammunitions",
        "android",
        "cancer",
        "firearms",
        "handicap",
        "uavs",
        "ukhsa-culture-collections",
    }
)

# Galaxy type → rdf:type label mapping
GALAXY_TYPE_LABELS = {
    "threat-actor": "ThreatActor",
    "ransomware": "Ransomware",
    "botnet": "Botnet",
    "rat": "RAT",
    "exploit-kit": "ExploitKit",
    "tool": "MISPTool",
    "backdoor": "Backdoor",
    "banker": "Banker",
    "stealer": "Stealer",
    "cryptominers": "Cryptominer",
    "malpedia": "MalpediaEntry",
    "branded_vulnerability": "BrandedVulnerability",
    "country": "Country",
    "region": "Region",
    "sector": "Sector",
    "surveillance-vendor": "SurveillanceVendor",
    "intelligence-agencies": "IntelligenceAgency",
    "microsoft-activity-group": "MicrosoftActivityGroup",
    "stalkerware": "Stalkerware",
    "terrorist-groups": "TerroristGroup",
    "tidal-campaigns": "TidalCampaign",
    "tidal-groups": "TidalGroup",
    "tidal-software": "TidalSoftware",
    "tidal-tactic": "TidalTactic",
    "tidal-technique": "TidalTechnique",
    "tidal-references": "TidalReference",
    "sigma-rules": "SigmaRule",
}

# Relationship types from the `related` array that get their own predicate
KNOWN_RELATION_TYPES = frozenset(
    {
        "similar-to",
        "uses",
        "used-by",
        "variant-of",
        "subtechnique-of",
        "targets",
        "attributed-to",
    }
)

# Regex to detect ATT&CK IDs in synonyms or external_id (e.g., T1059, G0006, S0154)
_ATTACK_ID_RE = re.compile(r"^[TGSC]\d{4}(\.\d{3})?$")


def download_misp_galaxy(cache_dir: str | None = None) -> str:
    """Download MISP Galaxy repo ZIP, returning path to the extracted directory."""
    return str(download_github_zip("MISP", "misp-galaxy", "misp-galaxy.zip", "main", cache_dir))


def _type_to_label(galaxy_type: str) -> str:
    """Convert a galaxy type string to a PascalCase rdf:type label."""
    label = GALAXY_TYPE_LABELS.get(galaxy_type)
    if label:
        return label
    # Fallback: convert kebab-case / snake_case to PascalCase
    return "".join(word.capitalize() for word in re.split(r"[-_]", galaxy_type))


def _find_clusters_dir(extract_dir: str) -> Path:
    """Locate the clusters/ directory inside the extracted repo."""
    base = Path(extract_dir)
    # download_github_zip extracts to a subdirectory like misp-galaxy-main/
    for candidate in [base / "clusters", *base.iterdir()]:
        if candidate.is_dir() and (candidate / "clusters").is_dir():
            return candidate / "clusters"
        if candidate.name == "clusters" and candidate.is_dir():
            return candidate
    raise FileNotFoundError(f"No clusters/ directory found in {extract_dir}")


def _value_triples(entry: dict, galaxy_type: str, is_mitre: bool) -> list[tuple[str, str, str]]:
    """Extract triples from a single cluster value entry."""
    uuid = entry.get("uuid", "")
    if not uuid:
        return []

    subject = f"misp:{uuid}"
    triples: list[tuple[str, str, str]] = []
    meta = entry.get("meta", {})

    # Entity property triples (skip for MITRE clusters to avoid ATT&CK duplication)
    if not is_mitre:
        triples.append((subject, "rdf:type", _type_to_label(galaxy_type)))

        if entry.get("value"):
            triples.append((subject, "name", str(entry["value"])))
        if entry.get("description"):
            triples.append((subject, "description", str(entry["description"])))

        triples.append((subject, "galaxy", galaxy_type))

        for syn in meta.get("synonyms", []):
            if syn:
                triples.append((subject, "synonym", str(syn)))
                if _ATTACK_ID_RE.match(str(syn)):
                    triples.append((subject, "related-attack-id", str(syn)))

        if meta.get("country"):
            triples.append((subject, "country", str(meta["country"])))

        if meta.get("cfr-suspected-state-sponsor"):
            triples.append(
                (subject, "cfr-suspected-state-sponsor", str(meta["cfr-suspected-state-sponsor"]))
            )

        for victim in meta.get("cfr-suspected-victims", []):
            if victim:
                triples.append((subject, "targets-country", str(victim)))

        for cat in meta.get("cfr-target-category", []):
            if cat:
                triples.append((subject, "targets-sector", str(cat)))

        if meta.get("attribution-confidence"):
            triples.append((subject, "attribution-confidence", str(meta["attribution-confidence"])))

    # Cross-link to ATT&CK via external_id (MITRE clusters)
    ext_id = meta.get("external_id", "")
    if ext_id and _ATTACK_ID_RE.match(ext_id):
        triples.append((subject, "related-attack-id", ext_id))

    # Relationship triples from the `related` array
    for rel in entry.get("related", []):
        dest_uuid = rel.get("dest-uuid", "")
        rel_type = rel.get("type", "")
        if not dest_uuid or not rel_type:
            continue

        predicate = rel_type if rel_type in KNOWN_RELATION_TYPES else "misp-related"
        triples.append((subject, predicate, f"misp:{dest_uuid}"))

    return triples


def extract_misp_galaxy_triples(extract_dir: str):
    """Yield SPO triples from all MISP Galaxy cluster JSON files."""
    clusters_dir = _find_clusters_dir(extract_dir)
    cluster_files = sorted(clusters_dir.glob("*.json"))
    logger.info("Found %d cluster files in %s", len(cluster_files), clusters_dir)

    total = 0
    for cluster_file in cluster_files:
        cluster_name = cluster_file.stem
        if cluster_name in SKIP_CLUSTERS:
            logger.debug("Skipping non-security cluster: %s", cluster_name)
            continue

        is_mitre = cluster_name.startswith("mitre-")

        try:
            data = json.loads(cluster_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to read %s: %s", cluster_file, e)
            continue

        galaxy_type = data.get("type", cluster_name)
        values = data.get("values", [])

        for entry in values:
            entry_triples = _value_triples(entry, galaxy_type, is_mitre)
            total += len(entry_triples)
            yield from entry_triples

        logger.debug(
            "%s: %d entries (%s)",
            cluster_name,
            len(values),
            "relationships only" if is_mitre else "full",
        )

    logger.info("Extracted %d MISP Galaxy triples total", total)


if __name__ == "__main__":
    import argparse

    from common import write_triples_streaming

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description="MISP Galaxy → KG Triples (Parquet)")
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument("--cache-dir", type=str, default=None)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    path = download_misp_galaxy(args.cache_dir)
    write_triples_streaming(
        extract_misp_galaxy_triples(path), args.output_dir / "misp_galaxy.parquet"
    )
