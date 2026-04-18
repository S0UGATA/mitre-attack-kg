"""MITRE CAR (Cyber Analytics Repository) YAML → Knowledge Graph SPO Triples."""

import logging
from pathlib import Path

import yaml

from common import download_github_zip, get_object_type, meta_json

logger = logging.getLogger(__name__)

SOURCE = "car"


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


def _t(s: str, p: str, o: str, m: str = "") -> tuple[str, str, str, str, str, str]:
    return (s, p, o, SOURCE, get_object_type(p), m)


def _analytic_triples(analytic: dict) -> list[tuple[str, str, str, str, str, str]]:
    """Extract triples from a single CAR analytic YAML."""
    aid = analytic.get("id", "")
    if not aid:
        return []

    # Entity-level meta: implementations and references
    entity_meta: dict = {}
    implementations = analytic.get("implementations", [])
    if implementations:
        impl_entries = []
        for impl in implementations:
            entry: dict = {}
            if impl.get("type"):
                entry["type"] = impl["type"]
            if impl.get("name"):
                entry["name"] = impl["name"]
            if impl.get("description"):
                entry["description"] = impl["description"]
            if impl.get("code"):
                entry["code"] = impl["code"]
            if entry:
                impl_entries.append(entry)
        if impl_entries:
            entity_meta["implementations"] = impl_entries

    refs = analytic.get("references", [])
    if refs:
        entity_meta["references"] = refs

    data_sources = analytic.get("data_model_references", [])
    if data_sources:
        entity_meta["data_model_references"] = data_sources

    triples = [_t(aid, "rdf:type", "Analytic", meta_json(entity_meta))]

    if analytic.get("title"):
        triples.append(_t(aid, "title", analytic["title"]))
    if analytic.get("description"):
        triples.append(_t(aid, "description", analytic["description"]))
    if analytic.get("submission_date"):
        triples.append(_t(aid, "submission-date", str(analytic["submission_date"])))
    if analytic.get("information_domain"):
        triples.append(_t(aid, "information-domain", str(analytic["information_domain"])))

    for platform in analytic.get("platforms", []):
        triples.append(_t(aid, "platform", platform))

    for subtype in analytic.get("subtypes", []):
        triples.append(_t(aid, "subtype", subtype))

    for atype in analytic.get("analytic_types", []):
        triples.append(_t(aid, "analytic-type", atype))

    for cov in analytic.get("coverage", []):
        tech = cov.get("technique", "")
        if tech:
            triples.append(_t(aid, "detects-technique", tech))

            coverage_level = cov.get("coverage", "")
            if coverage_level:
                triples.append(_t(aid, "coverage-level", f"{tech}:{coverage_level}"))

            for tactic in cov.get("tactics", []):
                triples.append(_t(aid, "covers-tactic", tactic))

            for subtech in cov.get("subtechniques", []):
                triples.append(_t(aid, "detects-subtechnique", subtech))

    for mapping in analytic.get("d3fend_mappings", []):
        d3f_id = mapping.get("id", "")
        if d3f_id:
            triples.append(_t(aid, "maps-to-d3fend", d3f_id))

    return triples


def extract_car_triples(extract_dir: str) -> list[tuple[str, str, str, str, str, str]]:
    """Extract SPO triples from all CAR analytic YAML files."""
    triples: list[tuple[str, str, str, str, str, str]] = []
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
