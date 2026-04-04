"""MITRE CAR (Cyber Analytics Repository) YAML → Knowledge Graph SPO Triples."""

import logging
from pathlib import Path

import yaml

from common import download_github_zip

logger = logging.getLogger(__name__)


def download_car(cache_dir: str | None = None) -> str:
    """Download CAR repo ZIP, returning path to the extraction directory."""
    return str(download_github_zip("mitre-attack", "car", "car-master.zip", "master", cache_dir))


def _find_analytics_dir(extract_dir: str) -> Path:
    """Locate the analytics directory inside the extraction."""
    base = Path(extract_dir)
    analytics_dir = base / "car-master" / "analytics"
    if not analytics_dir.exists():
        for d in base.iterdir():
            if d.is_dir() and (d / "analytics").exists():
                return d / "analytics"
    return analytics_dir


def _analytic_triples(analytic: dict) -> list[tuple[str, str, str]]:
    """Extract triples from a single CAR analytic YAML."""
    aid = analytic.get("id", "")
    if not aid:
        return []

    triples = [
        (aid, "rdf:type", "Analytic"),
    ]

    if analytic.get("title"):
        triples.append((aid, "title", analytic["title"]))
    if analytic.get("description"):
        triples.append((aid, "description", analytic["description"]))
    if analytic.get("submission_date"):
        triples.append((aid, "submission-date", str(analytic["submission_date"])))
    if analytic.get("information_domain"):
        triples.append((aid, "information-domain", str(analytic["information_domain"])))

    for platform in analytic.get("platforms", []):
        triples.append((aid, "platform", platform))

    for subtype in analytic.get("subtypes", []):
        triples.append((aid, "subtype", subtype))

    for atype in analytic.get("analytic_types", []):
        triples.append((aid, "analytic-type", atype))

    # Coverage → ATT&CK technique mappings
    for cov in analytic.get("coverage", []):
        tech = cov.get("technique", "")
        if tech:
            triples.append((aid, "detects-technique", tech))

            coverage_level = cov.get("coverage", "")
            if coverage_level:
                triples.append((aid, f"coverage-{tech}", coverage_level))

            for tactic in cov.get("tactics", []):
                triples.append((aid, "covers-tactic", tactic))

            for subtech in cov.get("subtechniques", []):
                triples.append((aid, "detects-subtechnique", subtech))

    # D3FEND mappings
    for mapping in analytic.get("d3fend_mappings", []):
        d3f_id = mapping.get("id", "")
        if d3f_id:
            triples.append((aid, "maps-to-d3fend", d3f_id))

    return triples


def extract_car_triples(extract_dir: str) -> list[tuple[str, str, str]]:
    """Extract SPO triples from all CAR analytic YAML files."""
    triples: list[tuple[str, str, str]] = []
    analytics_path = _find_analytics_dir(extract_dir)

    yaml_files = sorted(analytics_path.glob("*.yaml"))
    logger.info("Found %d CAR analytics YAML files", len(yaml_files))

    for yaml_file in yaml_files:
        try:
            with open(yaml_file) as f:
                analytic = yaml.safe_load(f)
            if analytic:
                triples.extend(_analytic_triples(analytic))
        except (yaml.YAMLError, KeyError, ValueError) as e:
            logger.warning("Failed to parse %s: %s", yaml_file, e)

    return triples


if __name__ == "__main__":
    import argparse

    from common import triples_to_dataframe, write_parquet

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description="CAR → KG Triples (Parquet)")
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument("--cache-dir", type=str, default=None)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    path = download_car(args.cache_dir)
    df = triples_to_dataframe(extract_car_triples(path))
    write_parquet(df, args.output_dir / "car.parquet")
