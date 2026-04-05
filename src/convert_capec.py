"""CAPEC XML → Knowledge Graph SPO Triples."""

import logging
from xml.etree import ElementTree as ET

from common import RELATION_PREDICATES, download_file, xml_text

logger = logging.getLogger(__name__)

CAPEC_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"
NS = {"capec": "http://capec.mitre.org/capec-3", "xhtml": "http://www.w3.org/1999/xhtml"}


def download_capec(cache_dir: str | None = None) -> str:
    """Download CAPEC XML, returning the local file path."""
    return str(download_file(CAPEC_URL, "capec_latest.xml", cache_dir))


def _property_triples(capec_id: str, ap: ET.Element) -> list[tuple[str, str, str]]:
    """Extract property triples from a single CAPEC attack pattern."""
    triples = [
        (capec_id, "rdf:type", "AttackPattern"),
    ]
    name = ap.get("Name", "")
    if name:
        triples.append((capec_id, "name", name))
    abstraction = ap.get("Abstraction", "")
    if abstraction:
        triples.append((capec_id, "abstraction", abstraction))
    status = ap.get("Status", "")
    if status:
        triples.append((capec_id, "status", status))

    desc = xml_text(ap.find("capec:Description", NS))
    if desc:
        triples.append((capec_id, "description", desc))

    likelihood = ap.findtext("capec:Likelihood_Of_Attack", namespaces=NS)
    if likelihood:
        triples.append((capec_id, "likelihood", likelihood))

    severity = ap.findtext("capec:Typical_Severity", namespaces=NS)
    if severity:
        triples.append((capec_id, "severity", severity))

    return triples


def _relationship_triples(capec_id: str, ap: ET.Element) -> list[tuple[str, str, str]]:
    """Extract relationship triples (CAPEC-CAPEC, CAPEC-CWE, CAPEC-ATT&CK)."""
    triples: list[tuple[str, str, str]] = []

    for rel in ap.findall(".//capec:Related_Attack_Pattern", NS):
        pred = RELATION_PREDICATES.get(rel.get("Nature", ""))
        target_id = rel.get("CAPEC_ID", "")
        if pred and target_id:
            triples.append((capec_id, pred, f"CAPEC-{target_id}"))

    for rw in ap.findall(".//capec:Related_Weakness", NS):
        cwe_id = rw.get("CWE_ID", "")
        if cwe_id:
            triples.append((capec_id, "related-weakness", f"CWE-{cwe_id}"))

    for tm in ap.findall(".//capec:Taxonomy_Mapping", NS):
        if tm.get("Taxonomy_Name") == "ATTACK":
            entry_id = tm.findtext("capec:Entry_ID", namespaces=NS)
            if entry_id:
                triples.append((capec_id, "maps-to-technique", f"T{entry_id}"))

    return triples


def _consequence_triples(capec_id: str, ap: ET.Element) -> list[tuple[str, str, str]]:
    """Extract consequence triples (scope and impact)."""
    triples: list[tuple[str, str, str]] = []
    for cons in ap.findall(".//capec:Consequence", NS):
        for scope in cons.findall("capec:Scope", NS):
            if scope.text:
                triples.append((capec_id, "consequence-scope", scope.text.strip()))
        for impact in cons.findall("capec:Impact", NS):
            if impact.text:
                triples.append((capec_id, "consequence-impact", impact.text.strip()))
    return triples


def extract_capec_triples(xml_path: str) -> list[tuple[str, str, str]]:
    """Extract SPO triples from CAPEC XML."""
    tree = ET.parse(xml_path)  # nosec B314 — trusted MITRE data
    root = tree.getroot()
    triples: list[tuple[str, str, str]] = []

    for ap in root.findall(".//capec:Attack_Pattern", NS):
        if ap.get("Status", "") in ("Deprecated", "Obsolete"):
            continue

        capec_id = f"CAPEC-{ap.get('ID')}"
        triples.extend(_property_triples(capec_id, ap))
        triples.extend(_relationship_triples(capec_id, ap))
        triples.extend(_consequence_triples(capec_id, ap))

    return triples


if __name__ == "__main__":
    import argparse
    from pathlib import Path

    from common import triples_to_dataframe, write_parquet

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description="CAPEC XML → KG Triples (Parquet)")
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument("--cache-dir", type=str, default=None)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    path = download_capec(args.cache_dir)
    df = triples_to_dataframe(extract_capec_triples(path))
    write_parquet(df, args.output_dir / "capec.parquet")
