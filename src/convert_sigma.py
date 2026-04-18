"""SigmaHQ Detection Rules YAML → Knowledge Graph SPO Triples."""

import logging
import re
from collections.abc import Iterator
from pathlib import Path

import requests
import yaml

from common import SOURCE_DIR, get_object_type, github_api_headers, meta_json, safe_zip_extract

logger = logging.getLogger(__name__)

SOURCE = "sigma"

SIGMA_RELEASES_API = "https://api.github.com/repos/SigmaHQ/sigma/releases/latest"


def _t(s: str, p: str, o: str, m: str = "") -> tuple[str, str, str, str, str, str]:
    return (s, p, o, SOURCE, get_object_type(p), m)


def download_sigma(cache_dir: str | None = None) -> str:
    """Download sigma_all_rules.zip from the latest SigmaHQ release.

    Returns path to the extraction directory containing YAML rule files.
    """
    cache = Path(cache_dir) if cache_dir else SOURCE_DIR
    cache.mkdir(parents=True, exist_ok=True)

    logger.info("Fetching latest SigmaHQ release info ...")
    resp = requests.get(SIGMA_RELEASES_API, headers=github_api_headers(), timeout=30)
    resp.raise_for_status()
    release = resp.json()
    tag = release["tag_name"]

    # Find sigma_all_rules.zip asset
    asset = None
    for a in release.get("assets", []):
        if a["name"] == "sigma_all_rules.zip":
            asset = a
            break

    if not asset:
        raise RuntimeError(f"No sigma_all_rules.zip asset in release {tag}")

    zip_name = f"sigma_all_rules_{tag}.zip"
    zip_path = cache / zip_name
    extract_dir = cache / f"sigma_rules_{tag}"

    if extract_dir.exists() and next(extract_dir.rglob("*.yml"), None):
        logger.info("Using cached Sigma rules at %s (release %s)", extract_dir, tag)
        return str(extract_dir)

    if not zip_path.exists():
        logger.info("Downloading %s (%d KB) ...", asset["name"], asset["size"] // 1000)
        download_url = asset["browser_download_url"]
        resp = requests.get(download_url, timeout=300)
        resp.raise_for_status()
        zip_path.write_bytes(resp.content)
        logger.info("Saved %s (%d bytes)", zip_path, len(resp.content))

    logger.info("Extracting %s ...", zip_path)
    extract_dir.mkdir(parents=True, exist_ok=True)
    safe_zip_extract(zip_path, extract_dir)
    logger.info("Extracted Sigma rules to %s", extract_dir)

    return str(extract_dir)


# Regex to match ATT&CK technique tags: attack.tNNNN or attack.tNNNN.NNN
_TECHNIQUE_RE = re.compile(r"^attack\.t(\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
# Regex to match CVE tags: cve.YYYY.NNNN
_CVE_RE = re.compile(r"^cve\.(\d{4}\.\d+)$", re.IGNORECASE)


def _rule_triples(rule: dict) -> list[tuple[str, str, str, str, str, str]]:
    """Extract triples from a single Sigma rule."""
    rule_id = rule.get("id", "")
    if not rule_id:
        return []

    # Entity-level meta: false_positives, references
    entity_meta: dict = {}
    fps = rule.get("falsepositives")
    if fps and isinstance(fps, list):
        entity_meta["false_positives"] = [str(fp) for fp in fps if fp]
    refs = rule.get("references")
    if refs and isinstance(refs, list):
        entity_meta["references"] = [str(r) for r in refs if r]

    triples: list[tuple[str, str, str, str, str, str]] = [
        _t(rule_id, "rdf:type", "SigmaRule", meta_json(entity_meta)),
    ]

    if rule.get("title"):
        triples.append(_t(rule_id, "title", str(rule["title"])))
    if rule.get("description"):
        triples.append(_t(rule_id, "description", str(rule["description"])))
    if rule.get("status"):
        triples.append(_t(rule_id, "status", str(rule["status"])))
    if rule.get("level"):
        triples.append(_t(rule_id, "level", str(rule["level"])))
    if rule.get("author"):
        triples.append(_t(rule_id, "author", str(rule["author"])))
    if rule.get("date"):
        triples.append(_t(rule_id, "date", str(rule["date"])))

    # Logsource
    logsource = rule.get("logsource", {})
    if logsource.get("category"):
        triples.append(_t(rule_id, "logsource-category", str(logsource["category"])))
    if logsource.get("product"):
        triples.append(_t(rule_id, "logsource-product", str(logsource["product"])))
    if logsource.get("service"):
        triples.append(_t(rule_id, "logsource-service", str(logsource["service"])))

    # Tags → ATT&CK technique links and CVE links
    for tag in rule.get("tags", []):
        tag_str = str(tag).strip()

        # ATT&CK technique: attack.t1059 or attack.t1059.001
        match = _TECHNIQUE_RE.match(tag_str)
        if match:
            tech_id = "T" + match.group(1).upper()
            triples.append(_t(rule_id, "detects-technique", tech_id))
            continue

        # CVE reference: cve.2024.1234
        match = _CVE_RE.match(tag_str)
        if match:
            cve_id = "CVE-" + match.group(1).replace(".", "-", 1)
            triples.append(_t(rule_id, "related-cve", cve_id))

    return triples


def extract_sigma_triples(rules_dir: str) -> Iterator[tuple[str, str, str, str, str, str]]:
    """Yield SPO triples from all Sigma rule YAML files."""
    rules_path = Path(rules_dir)

    yaml_files = list(rules_path.rglob("*.yml"))
    logger.info("Found %d Sigma rule YAML files", len(yaml_files))

    for yaml_file in yaml_files:
        try:
            with open(yaml_file) as f:
                rule = yaml.safe_load(f)
            if rule and isinstance(rule, dict):
                yield from _rule_triples(rule)
        except (yaml.YAMLError, KeyError, ValueError) as e:
            logger.warning("Failed to parse %s: %s", yaml_file, e)


if __name__ == "__main__":
    import argparse

    from common import write_triples_streaming

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description="Sigma → KG Triples (Parquet)")
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument("--cache-dir", type=str, default=None)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    path = download_sigma(args.cache_dir)
    write_triples_streaming(extract_sigma_triples(path), args.output_dir / "sigma.parquet")
