"""CWE XML → Knowledge Graph SPO Triples."""

import logging
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

from common import (
    RELATION_PREDICATES,
    SOURCE_DIR,
    download_file,
    get_object_type,
    meta_json,
    xml_text,
)

logger = logging.getLogger(__name__)

SOURCE = "cwe"

CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
NS = {"cwe": "http://cwe.mitre.org/cwe-7", "xhtml": "http://www.w3.org/1999/xhtml"}


def download_cwe(cache_dir: str | None = None) -> str:
    """Download CWE XML ZIP, extract, and return the local XML file path."""
    search_dir = Path(cache_dir) if cache_dir else SOURCE_DIR
    existing = list(search_dir.glob("cwec_*.xml"))
    if existing:
        logger.info("Using cached %s", existing[0])
        return str(existing[0])

    zip_path = download_file(CWE_URL, "cwec_latest.xml.zip", cache_dir)
    with zipfile.ZipFile(zip_path) as zf:
        xml_name = next(
            (n for n in zf.namelist() if n.endswith(".xml")),
            None,
        )
        if not xml_name:
            raise FileNotFoundError(f"No .xml file found in {zip_path}")
        resolved = zip_path.parent.resolve()
        target = (zip_path.parent / xml_name).resolve()
        if not str(target).startswith(str(resolved)):
            raise ValueError(f"Zip entry {xml_name!r} would escape extraction directory")
        zf.extract(xml_name, zip_path.parent)
        xml_path = zip_path.parent / xml_name

    logger.info("Extracted %s (%d bytes)", xml_path, xml_path.stat().st_size)
    return str(xml_path)


def _t(s: str, p: str, o: str, m: str = "") -> tuple[str, str, str, str, str, str]:
    return (s, p, o, SOURCE, get_object_type(p), m)


def _property_triples(
    cwe_id: str,
    weakness: ET.Element,
) -> list[tuple[str, str, str, str, str, str]]:
    """Extract property triples from a single CWE weakness."""
    # Build entity-level meta
    entity_meta: dict = {}

    # Detection methods
    det_methods = []
    for det in weakness.findall(".//cwe:Detection_Method", NS):
        method = det.findtext("cwe:Method", namespaces=NS)
        effectiveness = det.findtext("cwe:Effectiveness", namespaces=NS)
        desc = xml_text(det.find("cwe:Description", NS))
        entry: dict = {}
        if method:
            entry["method"] = method.strip()
        if effectiveness:
            entry["effectiveness"] = effectiveness.strip()
        if desc:
            entry["description"] = desc
        if entry:
            det_methods.append(entry)
    if det_methods:
        entity_meta["detection_methods"] = det_methods

    # Potential mitigations
    mits = []
    for mit in weakness.findall(".//cwe:Potential_Mitigation", NS):
        phase = mit.findtext("cwe:Phase", namespaces=NS)
        desc = xml_text(mit.find("cwe:Description", NS))
        effectiveness = mit.findtext("cwe:Effectiveness", namespaces=NS)
        entry = {}
        if phase:
            entry["phase"] = phase.strip()
        if desc:
            entry["description"] = desc
        if effectiveness:
            entry["effectiveness"] = effectiveness.strip()
        if entry:
            mits.append(entry)
    if mits:
        entity_meta["mitigations"] = mits

    # Observed examples
    examples = []
    for ex in weakness.findall(".//cwe:Observed_Example", NS):
        ref = ex.findtext("cwe:Reference", namespaces=NS)
        desc = xml_text(ex.find("cwe:Description", NS))
        if ref:
            examples.append(
                {"reference": ref.strip(), "description": desc}
                if desc
                else {"reference": ref.strip()}
            )
    if examples:
        entity_meta["observed_examples"] = examples

    triples = [
        _t(cwe_id, "rdf:type", "Weakness", meta_json(entity_meta)),
    ]
    name = weakness.get("Name", "")
    if name:
        triples.append(_t(cwe_id, "name", name))
    abstraction = weakness.get("Abstraction", "")
    if abstraction:
        triples.append(_t(cwe_id, "abstraction", abstraction))
    status = weakness.get("Status", "")
    if status:
        triples.append(_t(cwe_id, "status", status))

    desc = xml_text(weakness.find("cwe:Description", NS))
    if desc:
        triples.append(_t(cwe_id, "description", desc))

    likelihood = weakness.findtext("cwe:Likelihood_Of_Exploit", namespaces=NS)
    if likelihood:
        triples.append(_t(cwe_id, "likelihood-of-exploit", likelihood.strip()))

    return triples


def _relationship_triples(
    cwe_id: str,
    weakness: ET.Element,
) -> list[tuple[str, str, str, str, str, str]]:
    """Extract relationship triples (CWE-CWE and CWE-CAPEC)."""
    triples: list[tuple[str, str, str, str, str, str]] = []

    for rel in weakness.findall(".//cwe:Related_Weakness", NS):
        pred = RELATION_PREDICATES.get(rel.get("Nature", ""))
        target_id = rel.get("CWE_ID", "")
        if pred and target_id:
            triples.append(_t(cwe_id, pred, f"CWE-{target_id}"))

    for rap in weakness.findall(".//cwe:Related_Attack_Pattern", NS):
        capec_id = rap.get("CAPEC_ID", "")
        if capec_id:
            triples.append(_t(cwe_id, "related-attack-pattern", f"CAPEC-{capec_id}"))

    return triples


def _platform_triples(
    cwe_id: str,
    weakness: ET.Element,
) -> list[tuple[str, str, str, str, str, str]]:
    """Extract applicable platform triples."""
    triples: list[tuple[str, str, str, str, str, str]] = []
    platforms = weakness.find("cwe:Applicable_Platforms", NS)
    if platforms is None:
        return triples

    for tag in ("Language", "Technology", "Operating_System", "Architecture"):
        for el in platforms.findall(f"cwe:{tag}", NS):
            name = el.get("Name") or el.get("Class")
            if name and name != "Not Language-Specific":
                triples.append(_t(cwe_id, "platform", name))

    return triples


def _consequence_triples(
    cwe_id: str,
    weakness: ET.Element,
) -> list[tuple[str, str, str, str, str, str]]:
    """Extract consequence and introduction phase triples."""
    triples: list[tuple[str, str, str, str, str, str]] = []

    for cons in weakness.findall(".//cwe:Consequence", NS):
        for scope in cons.findall("cwe:Scope", NS):
            if scope.text:
                triples.append(_t(cwe_id, "consequence-scope", scope.text.strip()))
        for impact in cons.findall("cwe:Impact", NS):
            if impact.text:
                triples.append(_t(cwe_id, "consequence-impact", impact.text.strip()))

    for intro in weakness.findall(".//cwe:Introduction", NS):
        phase = intro.findtext("cwe:Phase", namespaces=NS)
        if phase:
            triples.append(_t(cwe_id, "introduction-phase", phase.strip()))

    return triples


def extract_cwe_triples(xml_path: str) -> list[tuple[str, str, str, str, str, str]]:
    """Extract SPO triples from CWE XML."""
    tree = ET.parse(xml_path)  # nosec B314 — trusted MITRE data
    root = tree.getroot()
    triples: list[tuple[str, str, str, str, str, str]] = []

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
