"""CISA Vulnrichment (CVE enrichment) JSON → Knowledge Graph SPO Triples."""

import json
import logging
from collections.abc import Iterator
from pathlib import Path

from common import download_github_zip, extract_cvss_meta, get_object_type

logger = logging.getLogger(__name__)

SOURCE = "vulnrichment"


def download_vulnrichment(cache_dir: str | None = None) -> str:
    """Download Vulnrichment repo ZIP, returning path to the extracted directory."""
    return str(
        download_github_zip("cisagov", "vulnrichment", "vulnrichment.zip", "develop", cache_dir)
    )


def _t(s: str, p: str, o: str, m: str = "") -> tuple[str, str, str, str, str, str]:
    return (s, p, o, SOURCE, get_object_type(p), m)


def _extract_single_cve(cve_data: dict) -> list[tuple[str, str, str, str, str, str]]:
    """Extract enrichment triples from a single Vulnrichment CVE JSON file."""
    meta = cve_data.get("cveMetadata", {})
    cve_id = meta.get("cveId", "")
    if not cve_id:
        return []

    state = meta.get("state", "")
    if state == "REJECTED":
        return []

    triples: list[tuple[str, str, str, str, str, str]] = []

    for adp in cve_data.get("containers", {}).get("adp", []):
        # CVSS metrics from ADP
        for metric in adp.get("metrics", []):
            cvss, m = extract_cvss_meta(metric)
            if cvss:
                if cvss.get("baseScore") is not None:
                    triples.append(_t(cve_id, "adp-cvss-base-score", str(cvss["baseScore"]), m))
                if cvss.get("baseSeverity"):
                    triples.append(_t(cve_id, "adp-cvss-severity", cvss["baseSeverity"], m))

            # SSVC decision points
            other = metric.get("other", {})
            if other.get("type") == "ssvc":
                content = other.get("content", {})
                for option in content.get("options", []):
                    for key, value in option.items():
                        key_slug = key.lower().replace(" ", "-")
                        triples.append(_t(cve_id, f"ssvc-{key_slug}", str(value)))

        # CWE from ADP problemTypes
        for pt in adp.get("problemTypes", []):
            for desc in pt.get("descriptions", []):
                cwe_id = desc.get("cweId")
                if cwe_id:
                    triples.append(_t(cve_id, "adp-related-weakness", cwe_id))

        # Affected products from ADP
        for affected in adp.get("affected", []):
            for cpe_str in affected.get("cpes", []):
                triples.append(_t(cve_id, "adp-affects-cpe", cpe_str))

    return triples


def extract_vulnrichment_triples(data_dir: str) -> Iterator[tuple[str, str, str, str, str, str]]:
    """Yield SPO triples from all Vulnrichment CVE JSON files."""
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

    logger.info("Processed %d Vulnrichment files total", count)


if __name__ == "__main__":
    import argparse

    from common import write_triples_streaming

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description="Vulnrichment → KG Triples (Parquet)")
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument("--cache-dir", type=str, default=None)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    path = download_vulnrichment(args.cache_dir)
    write_triples_streaming(
        extract_vulnrichment_triples(path), args.output_dir / "vulnrichment.parquet"
    )
