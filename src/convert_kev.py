"""CISA KEV (Known Exploited Vulnerabilities) JSON → Knowledge Graph SPO Triples."""

import json
import logging
from pathlib import Path

from common import download_file, get_object_type

logger = logging.getLogger(__name__)

SOURCE = "kev"

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def download_kev(cache_dir: str | None = None) -> str:
    """Download KEV JSON, returning the local file path."""
    return str(download_file(KEV_URL, "known_exploited_vulnerabilities.json", cache_dir))


def _t(s: str, p: str, o: str, m: str = "") -> tuple[str, str, str, str, str, str]:
    return (s, p, o, SOURCE, get_object_type(p), m)


def extract_kev_triples(json_path: str) -> list[tuple[str, str, str, str, str, str]]:
    """Extract SPO triples from CISA KEV JSON."""
    with open(json_path) as f:
        data = json.load(f)

    triples: list[tuple[str, str, str, str, str, str]] = []

    for vuln in data.get("vulnerabilities", []):
        cve_id = vuln.get("cveID", "")
        if not cve_id:
            continue

        triples.append(_t(cve_id, "rdf:type", "KnownExploitedVulnerability"))

        if vuln.get("vendorProject"):
            triples.append(_t(cve_id, "kev-vendor", vuln["vendorProject"]))
        if vuln.get("product"):
            triples.append(_t(cve_id, "kev-product", vuln["product"]))
        if vuln.get("vulnerabilityName"):
            triples.append(_t(cve_id, "kev-name", vuln["vulnerabilityName"]))
        if vuln.get("shortDescription"):
            triples.append(_t(cve_id, "kev-description", vuln["shortDescription"]))
        if vuln.get("dateAdded"):
            triples.append(_t(cve_id, "kev-date-added", vuln["dateAdded"]))
        if vuln.get("requiredAction"):
            triples.append(_t(cve_id, "kev-required-action", vuln["requiredAction"]))
        if vuln.get("dueDate"):
            triples.append(_t(cve_id, "kev-due-date", vuln["dueDate"]))
        if vuln.get("knownRansomwareCampaignUse"):
            triples.append(_t(cve_id, "kev-ransomware-use", vuln["knownRansomwareCampaignUse"]))
        if vuln.get("notes"):
            triples.append(_t(cve_id, "kev-notes", vuln["notes"]))
        for cwe in vuln.get("cwes", []):
            if cwe:
                cwe_id = cwe if cwe.startswith("CWE-") else f"CWE-{cwe}"
                triples.append(_t(cve_id, "related-weakness", cwe_id))

    return triples


if __name__ == "__main__":
    import argparse

    from common import triples_to_dataframe, write_parquet

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description="CISA KEV → KG Triples (Parquet)")
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument("--cache-dir", type=str, default=None)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    path = download_kev(args.cache_dir)
    df = triples_to_dataframe(extract_kev_triples(path))
    write_parquet(df, args.output_dir / "kev.parquet")
