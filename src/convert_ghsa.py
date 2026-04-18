"""GitHub Security Advisories (GHSA) JSON → Knowledge Graph SPO Triples."""

import json
import logging
from collections.abc import Iterator
from pathlib import Path

from common import download_github_zip, get_object_type, meta_json

logger = logging.getLogger(__name__)

SOURCE = "ghsa"


def download_ghsa(cache_dir: str | None = None) -> str:
    """Download GHSA advisory database ZIP, returning path to the extraction directory."""
    return str(download_github_zip("github", "advisory-database", "ghsa.zip", "main", cache_dir))


def _find_reviewed_dir(extract_dir: str) -> Path:
    """Locate the github-reviewed advisories directory inside the extraction."""
    base = Path(extract_dir)
    reviewed_dir = base / "advisory-database-main" / "advisories" / "github-reviewed"
    if not reviewed_dir.exists():
        for d in base.iterdir():
            if d.is_dir():
                candidate = d / "advisories" / "github-reviewed"
                if candidate.exists():
                    return candidate
    return reviewed_dir


def _t(s: str, p: str, o: str, m: str = "") -> tuple[str, str, str, str, str, str]:
    return (s, p, o, SOURCE, get_object_type(p), m)


def _extract_single_advisory(advisory: dict) -> list[tuple[str, str, str, str, str, str]]:
    """Extract triples from a single GHSA advisory (OSV format)."""
    ghsa_id = advisory.get("id", "")
    if not ghsa_id:
        return []

    # Entity-level meta: references, credits
    entity_meta: dict = {}
    refs = advisory.get("references", [])
    if refs:
        ref_urls = [r.get("url") for r in refs if r.get("url")]
        if ref_urls:
            entity_meta["references"] = ref_urls

    credits_list = advisory.get("credits", [])
    if credits_list:
        credit_entries = []
        for c in credits_list:
            entry: dict = {}
            if c.get("type"):
                entry["type"] = c["type"]
            if c.get("name"):
                entry["name"] = c["name"]
            if entry:
                credit_entries.append(entry)
        if credit_entries:
            entity_meta["credits"] = credit_entries

    triples: list[tuple[str, str, str, str, str, str]] = [
        _t(ghsa_id, "rdf:type", "SecurityAdvisory", meta_json(entity_meta)),
    ]

    if advisory.get("summary"):
        triples.append(_t(ghsa_id, "summary", advisory["summary"]))

    if advisory.get("published"):
        triples.append(_t(ghsa_id, "date-published", advisory["published"]))
    if advisory.get("modified"):
        triples.append(_t(ghsa_id, "date-modified", advisory["modified"]))

    # CVE aliases
    for alias in advisory.get("aliases", []):
        if alias.startswith("CVE-"):
            triples.append(_t(ghsa_id, "related-cve", alias))

    # Severity (CVSS)
    for sev in advisory.get("severity", []):
        if sev.get("score"):
            triples.append(_t(ghsa_id, "cvss-vector", sev["score"]))

    # database_specific fields
    db_specific = advisory.get("database_specific", {})
    severity = db_specific.get("severity")
    if severity:
        triples.append(_t(ghsa_id, "severity", severity))

    # CWE IDs
    for cwe_id in db_specific.get("cwe_ids", []):
        triples.append(_t(ghsa_id, "related-weakness", cwe_id))

    # Affected packages
    for affected in advisory.get("affected", []):
        pkg = affected.get("package", {})
        ecosystem = pkg.get("ecosystem", "")
        name = pkg.get("name", "")
        if not name:
            continue

        pkg_id = f"{ecosystem}/{name}" if ecosystem else name

        # Build per-package meta: version ranges
        pkg_meta: dict = {}
        for rng in affected.get("ranges", []):
            range_type = rng.get("type", "")
            introduced = None
            last_affected = None
            for event in rng.get("events", []):
                if "introduced" in event:
                    introduced = event["introduced"]
                if "last_affected" in event:
                    last_affected = event["last_affected"]
            if introduced and introduced != "0":
                pkg_meta.setdefault("introduced", []).append(
                    f"{range_type}:{introduced}" if range_type else introduced
                )
            if last_affected:
                pkg_meta.setdefault("last_affected", []).append(last_affected)

        triples.append(_t(ghsa_id, "affects-package", pkg_id, meta_json(pkg_meta)))

        # Version ranges
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    triples.append(_t(ghsa_id, "fixed-in", f"{pkg_id}@{event['fixed']}"))

    return triples


def extract_ghsa_triples(extract_dir: str) -> Iterator[tuple[str, str, str, str, str, str]]:
    """Yield SPO triples from all GHSA advisory JSON files."""
    data_path = _find_reviewed_dir(extract_dir)
    count = 0

    for json_file in data_path.rglob("GHSA-*.json"):
        count += 1
        if count % 10_000 == 0:
            logger.info("  processed %d advisories", count)

        try:
            with open(json_file) as f:
                advisory = json.load(f)
            yield from _extract_single_advisory(advisory)
        except (json.JSONDecodeError, KeyError, ValueError, OSError) as e:
            logger.warning("Failed to parse %s: %s", json_file.name, e)

    logger.info("Processed %d GHSA advisories total", count)


if __name__ == "__main__":
    import argparse

    from common import write_triples_streaming

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description="GHSA → KG Triples (Parquet)")
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument("--cache-dir", type=str, default=None)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    path = download_ghsa(args.cache_dir)
    write_triples_streaming(extract_ghsa_triples(path), args.output_dir / "ghsa.parquet")
