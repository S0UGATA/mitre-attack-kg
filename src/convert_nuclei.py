"""Nuclei Templates YAML -> Knowledge Graph SPO Triples."""

import logging
import os
import re
from collections.abc import Iterator
from pathlib import Path

import yaml

from common import SOURCE_DIR, Triple, download_github_zip, make_triple_fn, truncate_text

logger = logging.getLogger(__name__)

SOURCE = "nuclei"

_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)
_CWE_TAG_RE = re.compile(r"^cwe-(\d+)$", re.IGNORECASE)
_CVE_TAG_RE = re.compile(r"^cve-(\d{4}-\d+)$", re.IGNORECASE)

SKIP_DIRS = {".github", "helpers", ".git", "code", "dns", "ssl", "headless", "workflows"}


_t = make_triple_fn(SOURCE)


def download_nuclei(cache_dir: str | None = None, *, force_download: bool = False) -> str:
    cache = Path(cache_dir) if cache_dir else SOURCE_DIR
    path = download_github_zip(
        "projectdiscovery",
        "nuclei-templates",
        "nuclei.zip",
        "main",
        cache,
        force_download=force_download,
    )
    return str(path)


def _template_triples(data: dict) -> list[Triple]:
    template_id = data.get("id", "")
    if not template_id:
        return []

    info = data.get("info", {})
    if not info or not isinstance(info, dict):
        return []

    eid = str(template_id)
    is_cve = bool(_CVE_RE.match(eid))
    if is_cve:
        eid = eid.upper()

    triples: list[Triple] = [
        _t(eid, "rdf:type", "NucleiTemplate"),
    ]

    name = info.get("name")
    if name:
        triples.append(_t(eid, "name", str(name)))

    severity = info.get("severity")
    if severity:
        triples.append(_t(eid, "severity", str(severity).lower()))

    author = info.get("author")
    if author:
        if isinstance(author, list):
            author = ",".join(str(a) for a in author)
        triples.append(_t(eid, "author", str(author)))

    desc = info.get("description")
    if desc:
        triples.append(_t(eid, "description", truncate_text(str(desc))))

    classification = info.get("classification", {}) or {}

    cwe_set: set[str] = set()
    cve_set: set[str] = set()

    for tag in info.get("tags", []):
        tag_str = str(tag).strip().lower()

        cwe_match = _CWE_TAG_RE.match(tag_str)
        if cwe_match:
            cwe_set.add(f"CWE-{cwe_match.group(1)}")
            continue

        if not is_cve:
            cve_match = _CVE_TAG_RE.match(tag_str)
            if cve_match:
                cve_set.add(f"CVE-{cve_match.group(1).upper()}")

    for cwe in classification.get("cwe-id") or []:
        if isinstance(cwe, str):
            cwe_str = cwe.strip()
            if cwe_str.startswith("CWE-"):
                cwe_set.add(cwe_str)

    if not is_cve:
        for cve in classification.get("cve-id") or []:
            if isinstance(cve, str):
                cve_str = cve.strip().upper()
                if cve_str.startswith("CVE-"):
                    cve_set.add(cve_str)

    for cwe in sorted(cwe_set):
        triples.append(_t(eid, "related-weakness", cwe))
    for cve in sorted(cve_set):
        triples.append(_t(eid, "related-cve", cve))

    cvss_score = classification.get("cvss-score")
    if cvss_score is not None:
        triples.append(_t(eid, "cvss-base-score", str(cvss_score)))

    cvss_metrics = classification.get("cvss-metrics")
    if cvss_metrics:
        triples.append(_t(eid, "cvss-vector", str(cvss_metrics)))

    return triples


def extract_nuclei_triples(
    repo_dir: str,
) -> Iterator[Triple]:
    repo_path = Path(repo_dir)

    yaml_files = []
    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if fname.endswith(".yaml"):
                yaml_files.append(Path(dirpath) / fname)

    logger.info("Found %d Nuclei template YAML files", len(yaml_files))

    for yaml_file in yaml_files:
        try:
            with open(yaml_file) as f:
                data = yaml.safe_load(f)
            if data and isinstance(data, dict):
                yield from _template_triples(data)
        except (yaml.YAMLError, KeyError, ValueError) as e:
            logger.warning("Failed to parse %s: %s", yaml_file, e)


if __name__ == "__main__":
    import argparse

    from common import write_triples_streaming

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description="Nuclei Templates -> KG Triples (Parquet)")
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument("--cache-dir", type=str, default=None)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    path = download_nuclei(args.cache_dir)
    write_triples_streaming(extract_nuclei_triples(path), args.output_dir / "nuclei.parquet")
