"""CVE (Common Vulnerabilities and Exposures) JSON 5.x → Knowledge Graph SPO Triples."""

import json
import logging
import re
import zipfile
from pathlib import Path

import requests

from common import SOURCE_DIR

logger = logging.getLogger(__name__)

CVELIST_API = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"


def download_cve(cache_dir: str | None = None) -> str:
    """Download CVE bulk ZIP from cvelistV5 GitHub releases.

    Returns the path to the extracted directory containing CVE JSON files.
    """
    cache = Path(cache_dir) if cache_dir else SOURCE_DIR
    cache.mkdir(parents=True, exist_ok=True)

    # Get latest release info
    logger.info("Fetching latest cvelistV5 release info ...")
    resp = requests.get(
        CVELIST_API,
        headers={"Accept": "application/vnd.github.v3+json"},
        timeout=30,
    )
    resp.raise_for_status()
    release = resp.json()
    tag = release["tag_name"]

    # Find the all_CVEs_at_midnight asset
    asset = None
    for a in release.get("assets", []):
        if "all_CVEs_at_midnight" in a["name"]:
            asset = a
            break

    if not asset:
        raise RuntimeError(f"No all_CVEs_at_midnight asset in release {tag}")

    zip_name = asset["name"]
    zip_path = cache / zip_name
    # Use the date portion of the zip name (e.g. "2026-04-04_all_CVEs_at_midnight")
    # as the extract dir, not the release tag which changes within the same day.
    zip_base = zip_name.split(".")[0]
    extract_dir = cache / f"cve_extracted_{zip_base}"

    # Check if already downloaded and extracted
    if extract_dir.exists() and next(extract_dir.rglob("CVE-*.json"), None) and zip_path.exists():
        logger.info("Using cached CVE data at %s (release %s)", extract_dir, tag)
        return str(extract_dir)

    # Download the ZIP
    if not zip_path.exists():
        logger.info("Downloading %s (%d MB) ...", zip_name, asset["size"] // 1_000_000)
        download_url = asset["browser_download_url"]
        resp = requests.get(download_url, timeout=600, stream=True)
        resp.raise_for_status()
        with open(zip_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)
        logger.info("Saved %s (%d bytes)", zip_path, zip_path.stat().st_size)

    # Extract (the release ZIP contains a nested cves.zip with the actual JSON files)
    logger.info("Extracting %s ...", zip_path)
    extract_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(extract_dir)

    # Check for nested cves.zip
    inner_zip = extract_dir / "cves.zip"
    if inner_zip.exists():
        logger.info("Extracting nested cves.zip ...")
        with zipfile.ZipFile(inner_zip) as zf:
            zf.extractall(extract_dir)
        inner_zip.unlink()

    logger.info("Extracted CVE data to %s", extract_dir)

    return str(extract_dir)


def _parse_cwe_id(description: str) -> str | None:
    """Extract CWE ID from a problemType description string like 'CWE-79 ...'."""
    match = re.match(r"(CWE-\d+)", description)
    return match.group(1) if match else None


def _extract_single_cve(cve_data: dict) -> list[tuple[str, str, str]]:
    """Extract triples from a single CVE JSON 5.x record."""
    meta = cve_data.get("cveMetadata", {})
    cve_id = meta.get("cveId", "")
    if not cve_id:
        return []

    state = meta.get("state", "")
    if state == "REJECTED":
        return []

    triples: list[tuple[str, str, str]] = [
        (cve_id, "rdf:type", "Vulnerability"),
    ]

    if state:
        triples.append((cve_id, "state", state))
    if meta.get("datePublished"):
        triples.append((cve_id, "date-published", meta["datePublished"]))
    if meta.get("dateUpdated"):
        triples.append((cve_id, "date-updated", meta["dateUpdated"]))
    if meta.get("assignerShortName"):
        triples.append((cve_id, "assigner", meta["assignerShortName"]))

    cna = cve_data.get("containers", {}).get("cna", {})

    # Description
    for desc in cna.get("descriptions", []):
        lang = desc.get("lang", "")
        if lang == "en" and desc.get("value"):
            triples.append((cve_id, "description", desc["value"]))
            break

    # Affected products
    for affected in cna.get("affected", []):
        vendor = affected.get("vendor", "")
        product = affected.get("product", "")
        if vendor:
            triples.append((cve_id, "vendor", vendor))
        if product:
            triples.append((cve_id, "product", product))

        # CPE strings if present
        for cpe_str in affected.get("cpes", []):
            triples.append((cve_id, "affects-cpe", cpe_str))

        # Platforms
        for platform in affected.get("platforms", []):
            triples.append((cve_id, "platform", platform))

    # Problem types (CWE links)
    for pt in cna.get("problemTypes", []):
        for desc in pt.get("descriptions", []):
            cwe_id_field = desc.get("cweId")
            if cwe_id_field:
                triples.append((cve_id, "related-weakness", cwe_id_field))
            elif desc.get("description"):
                cwe_id = _parse_cwe_id(desc["description"])
                if cwe_id:
                    triples.append((cve_id, "related-weakness", cwe_id))

    # CVSS metrics
    for metric in cna.get("metrics", []):
        cvss = metric.get("cvssV3_1") or metric.get("cvssV3_0") or metric.get("cvssV4_0")
        if cvss:
            if cvss.get("baseScore") is not None:
                triples.append((cve_id, "cvss-base-score", str(cvss["baseScore"])))
            if cvss.get("baseSeverity"):
                triples.append((cve_id, "cvss-severity", cvss["baseSeverity"]))

    return triples


def extract_cve_triples(data_dir: str):
    """Yield SPO triples from all CVE JSON files in the extracted directory.

    Returns a generator to avoid loading millions of triples into memory.
    """
    data_path = Path(data_dir)
    count = 0

    for json_file in data_path.rglob("CVE-*.json"):
        count += 1
        if count % 50_000 == 0:
            logger.info("  processed %d CVEs", count)

        try:
            with open(json_file) as f:
                cve_data = json.load(f)
            yield from _extract_single_cve(cve_data)
        except (json.JSONDecodeError, KeyError, ValueError, OSError) as e:
            logger.warning("Failed to parse %s: %s", json_file.name, e)

    logger.info("Processed %d CVE files total", count)


if __name__ == "__main__":
    import argparse

    from common import write_triples_streaming

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description="CVE → KG Triples (Parquet)")
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument("--cache-dir", type=str, default=None)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    path = download_cve(args.cache_dir)
    write_triples_streaming(extract_cve_triples(path), args.output_dir / "cve.parquet")
