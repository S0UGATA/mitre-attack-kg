"""CWE XML → Knowledge Graph SPO Triples."""

import logging
import tempfile
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

from common import RELATION_PREDICATES, download_file, xml_text

logger = logging.getLogger(__name__)

CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
NS = {"cwe": "http://cwe.mitre.org/cwe-7", "xhtml": "http://www.w3.org/1999/xhtml"}


def download_cwe(cache_dir: str | None = None) -> str:
    """Download CWE XML ZIP, extract, and return the local XML file path."""
    # Check for previously extracted XML (filename includes version)
    search_dir = Path(cache_dir) if cache_dir else Path(tempfile.gettempdir())
    existing = list(search_dir.glob("cwec_*.xml"))
    if existing:
        logger.info("Using cached %s", existing[0])
        return str(existing[0])

    zip_path = download_file(CWE_URL, "cwec_latest.xml.zip", cache_dir)
    with zipfile.ZipFile(zip_path) as zf:
        xml_name = next(n for n in zf.namelist() if n.endswith(".xml"))
        zf.extract(xml_name, zip_path.parent)
        xml_path = zip_path.parent / xml_name

    logger.info("Extracted %s (%d bytes)", xml_path, xml_path.stat().st_size)
    return str(xml_path)


def _property_triples(cwe_id: str, weakness: ET.Element) -> list[tuple[str, str, str]]:
    """Extract property triples from a single CWE weakness."""
    triples = [
        (cwe_id, "rdf:type", "Weakness"),
        (cwe_id, "name", weakness.get("Name", "")),
        (cwe_id, "abstraction", weakness.get("Abstraction", "")),
        (cwe_id, "status", weakness.get("Status", "")),
    ]

    desc = xml_text(weakness.find("cwe:Description", NS))
    if desc:
        triples.append((cwe_id, "description", desc))

    likelihood = weakness.findtext("cwe:Likelihood_Of_Exploit", namespaces=NS)
    if likelihood:
        triples.append((cwe_id, "likelihood-of-exploit", likelihood.strip()))

    return triples


def _relationship_triples(cwe_id: str, weakness: ET.Element) -> list[tuple[str, str, str]]:
    """Extract relationship triples (CWE-CWE and CWE-CAPEC)."""
    triples: list[tuple[str, str, str]] = []

    for rel in weakness.findall(".//cwe:Related_Weakness", NS):
        pred = RELATION_PREDICATES.get(rel.get("Nature", ""))
        target_id = rel.get("CWE_ID", "")
        if pred and target_id:
            triples.append((cwe_id, pred, f"CWE-{target_id}"))

    for rap in weakness.findall(".//cwe:Related_Attack_Pattern", NS):
        capec_id = rap.get("CAPEC_ID", "")
        if capec_id:
            triples.append((cwe_id, "related-attack-pattern", f"CAPEC-{capec_id}"))

    return triples


def _platform_triples(cwe_id: str, weakness: ET.Element) -> list[tuple[str, str, str]]:
    """Extract applicable platform triples."""
    triples: list[tuple[str, str, str]] = []
    platforms = weakness.find("cwe:Applicable_Platforms", NS)
    if platforms is None:
        return triples

    for tag in ("Language", "Technology", "Operating_System", "Architecture"):
        for el in platforms.findall(f"cwe:{tag}", NS):
            name = el.get("Name") or el.get("Class")
            if name and name != "Not Language-Specific":
                triples.append((cwe_id, "platform", name))

    return triples


def _consequence_triples(cwe_id: str, weakness: ET.Element) -> list[tuple[str, str, str]]:
    """Extract consequence and introduction phase triples."""
    triples: list[tuple[str, str, str]] = []

    for cons in weakness.findall(".//cwe:Consequence", NS):
        for scope in cons.findall("cwe:Scope", NS):
            if scope.text:
                triples.append((cwe_id, "consequence-scope", scope.text.strip()))
        for impact in cons.findall("cwe:Impact", NS):
            if impact.text:
                triples.append((cwe_id, "consequence-impact", impact.text.strip()))

    for intro in weakness.findall(".//cwe:Introduction", NS):
        phase = intro.findtext("cwe:Phase", namespaces=NS)
        if phase:
            triples.append((cwe_id, "introduction-phase", phase.strip()))

    return triples


def extract_cwe_triples(xml_path: str) -> list[tuple[str, str, str]]:
    """Extract SPO triples from CWE XML."""
    tree = ET.parse(xml_path)  # nosec B314 — trusted MITRE data
    root = tree.getroot()
    triples: list[tuple[str, str, str]] = []

    for weakness in root.findall(".//cwe:Weakness", NS):
        if weakness.get("Status", "") == "Deprecated":
            continue

        cwe_id = f"CWE-{weakness.get('ID')}"
        triples.extend(_property_triples(cwe_id, weakness))
        triples.extend(_relationship_triples(cwe_id, weakness))
        triples.extend(_platform_triples(cwe_id, weakness))
        triples.extend(_consequence_triples(cwe_id, weakness))

    return triples


if __name__ == "__main__":
    import argparse

    from common import triples_to_dataframe, write_parquet

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description="CWE XML → KG Triples (Parquet)")
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument("--cache-dir", type=str, default=None)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    path = download_cwe(args.cache_dir)
    df = triples_to_dataframe(extract_cwe_triples(path))
    write_parquet(df, args.output_dir / "cwe.parquet")
