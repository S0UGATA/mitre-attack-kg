"""OSV (Open Source Vulnerabilities) JSON -> Knowledge Graph SPO Triples."""

import json
import logging
import shutil
import zipfile
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from common import (
    SOURCE_DIR,
    Triple,
    download_file,
    make_triple_fn,
    meta_json,
    safe_zip_extract,
    truncate_text,
)

logger = logging.getLogger(__name__)

SOURCE = "osv"

OSV_BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com"

ECOSYSTEMS = [
    "Alpine",
    "Android",
    "Bitnami",
    "CRAN",
    "crates.io",
    "Debian",
    "GIT",
    "GitHub Actions",
    "Go",
    "Hex",
    "Linux",
    "Maven",
    "npm",
    "NuGet",
    "OSS-Fuzz",
    "Packagist",
    "Pub",
    "PyPI",
    "Rocky Linux",
    "RubyGems",
    "SwiftURL",
    "Ubuntu",
]


_t = make_triple_fn(SOURCE)


def _download_ecosystem(osv_dir: Path, ecosystem: str, *, force_download: bool = False) -> None:
    url = f"{OSV_BASE_URL}/{ecosystem}/all.zip"
    safe_name = ecosystem.replace(" ", "_").replace(".", "_")
    zip_name = f"osv_{safe_name}.zip"

    zip_path = download_file(url, zip_name, str(osv_dir), force_download=force_download)
    extract_dir = zip_path.parent / zip_path.stem
    if not force_download and extract_dir.exists() and any(extract_dir.iterdir()):
        return

    for old_dir in osv_dir.glob(f"osv_{safe_name}_*"):
        if old_dir.is_dir() and old_dir != extract_dir:
            try:
                shutil.rmtree(old_dir)
                logger.info("Cleaned up old OSV extraction dir %s", old_dir)
            except OSError:
                pass

    if force_download and extract_dir.exists():
        shutil.rmtree(extract_dir)
    extract_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Extracting %s ...", zip_path)
    try:
        safe_zip_extract(zip_path, extract_dir)
    except zipfile.BadZipFile:
        logger.warning("Re-downloading after corrupt zip: %s", zip_path.name)
        if extract_dir.exists():
            shutil.rmtree(extract_dir)
        zip_path = download_file(url, zip_name, str(osv_dir), force_download=True)
        extract_dir.mkdir(parents=True, exist_ok=True)
        safe_zip_extract(zip_path, extract_dir)


def download_osv(cache_dir: str | None = None, *, force_download: bool = False) -> str:
    cache = Path(cache_dir) if cache_dir else SOURCE_DIR
    osv_dir = cache / "osv"
    osv_dir.mkdir(parents=True, exist_ok=True)

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {
            pool.submit(_download_ecosystem, osv_dir, eco, force_download=force_download): eco
            for eco in ECOSYSTEMS
        }
        for future in as_completed(futures):
            eco = futures[future]
            try:
                future.result()
            except Exception as e:
                logger.warning("Failed to download/extract OSV ecosystem %s: %s", eco, e)

    return str(osv_dir)


def _vuln_triples(record: dict) -> list[Triple]:
    osv_id = record.get("id", "")
    if not osv_id:
        return []

    eid = str(osv_id)
    triples: list[Triple] = [
        _t(eid, "rdf:type", "OSVulnerability"),
    ]

    summary = record.get("summary")
    if summary:
        triples.append(_t(eid, "summary", truncate_text(str(summary))))

    published = record.get("published")
    if published:
        triples.append(_t(eid, "date-published", str(published)[:10]))

    modified = record.get("modified")
    if modified:
        triples.append(_t(eid, "date-modified", str(modified)[:10]))

    for alias in record.get("aliases", []):
        alias_str = str(alias).strip().upper()
        if alias_str.startswith("CVE-"):
            triples.append(_t(eid, "related-cve", alias_str))

    db_specific = record.get("database_specific", {}) or {}
    for cwe_id in db_specific.get("cwe_ids", []):
        cwe_str = str(cwe_id).strip().upper()
        if cwe_str.startswith("CWE-"):
            triples.append(_t(eid, "related-weakness", cwe_str))

    seen_packages: set[str] = set()
    seen_ecosystems: set[str] = set()
    for affected in record.get("affected", []):
        if not isinstance(affected, dict):
            continue
        pkg = affected.get("package", {}) or {}
        ecosystem = pkg.get("ecosystem", "")
        pkg_name = pkg.get("name", "")
        if ecosystem and pkg_name:
            pkg_key = f"{ecosystem}/{pkg_name}"
            if pkg_key not in seen_packages:
                seen_packages.add(pkg_key)
                # Collect version ranges from all range entries for this package
                pkg_meta: dict = {}
                for rng in affected.get("ranges", []):
                    if not isinstance(rng, dict):
                        continue
                    for event in rng.get("events", []):
                        if not isinstance(event, dict):
                            continue
                        introduced = event.get("introduced", "")
                        if introduced and introduced != "0":
                            pkg_meta.setdefault("introduced", []).append(introduced)
                        fixed = event.get("fixed", "")
                        if fixed:
                            pkg_meta.setdefault("fixed", []).append(fixed)
                            triples.append(_t(eid, "fixed-in", f"{pkg_key}@{fixed}"))
                triples.append(_t(eid, "affects-package", pkg_key, meta_json(pkg_meta)))
        if ecosystem and ecosystem not in seen_ecosystems:
            seen_ecosystems.add(ecosystem)
            triples.append(_t(eid, "ecosystem", str(ecosystem)))

    for sev in record.get("severity", []):
        if not isinstance(sev, dict):
            continue
        score = sev.get("score", "")
        if score:
            triples.append(_t(eid, "cvss-vector", str(score)))

    return triples


def extract_osv_triples(
    osv_dir: str,
) -> Iterator[Triple]:
    osv_path = Path(osv_dir)
    json_count = 0

    for extract_dir in sorted(osv_path.iterdir()):
        if not extract_dir.is_dir():
            continue
        if extract_dir.name.endswith(".zip"):
            continue

        for json_file in sorted(extract_dir.glob("*.json")):
            try:
                with open(json_file, encoding="utf-8") as f:
                    record = json.load(f)
                if record and isinstance(record, dict):
                    yield from _vuln_triples(record)
                    json_count += 1
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                logger.warning("Failed to parse %s: %s", json_file, e)

    logger.info("Processed %d OSV vulnerability records", json_count)


if __name__ == "__main__":
    import argparse

    from common import write_triples_streaming

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description="OSV -> KG Triples (Parquet)")
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument("--cache-dir", type=str, default=None)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    path = download_osv(args.cache_dir)
    write_triples_streaming(extract_osv_triples(path), args.output_dir / "osv.parquet")
