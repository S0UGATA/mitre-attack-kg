"""LOLBAS (Living Off The Land Binaries and Scripts) YAML -> Knowledge Graph SPO Triples."""

import logging
from collections.abc import Iterator
from pathlib import Path

import yaml

from common import SOURCE_DIR, Triple, download_github_zip, make_triple_fn, meta_json

logger = logging.getLogger(__name__)

SOURCE = "lolbas"


_t = make_triple_fn(SOURCE)


def download_lolbas(cache_dir: str | None = None, *, force_download: bool = False) -> str:
    cache = Path(cache_dir) if cache_dir else SOURCE_DIR
    path = download_github_zip(
        "LOLBAS-Project",
        "LOLBAS",
        "lolbas.zip",
        "master",
        cache,
        force_download=force_download,
    )
    return str(path)


def _binary_triples(data: dict) -> list[Triple]:
    name = data.get("Name", "")
    if not name:
        return []

    eid = name
    entity_meta: dict = {}
    refs = [str(r.get("Link") or r) for r in (data.get("Resources", [])) if r]
    if refs:
        entity_meta["references"] = refs

    triples: list[Triple] = [
        _t(eid, "rdf:type", "LOLBinary", meta_json(entity_meta)),
        _t(eid, "name", name),
    ]

    if data.get("Description"):
        triples.append(_t(eid, "description", str(data["Description"])))

    for cmd in data.get("Commands", []):
        if not isinstance(cmd, dict):
            continue
        mitre_id = cmd.get("MitreID")
        if mitre_id:
            triples.append(_t(eid, "maps-to-technique", str(mitre_id).upper()))
        category = cmd.get("Category")
        if category:
            triples.append(_t(eid, "category", str(category)))
        usecase = cmd.get("Usecase")
        if usecase:
            triples.append(_t(eid, "usecase", str(usecase)))
        privs = cmd.get("Privileges")
        if privs:
            triples.append(_t(eid, "privileges", str(privs)))
        os_name = cmd.get("OperatingSystem")
        if os_name:
            triples.append(_t(eid, "platform", str(os_name)))

    for fp in data.get("Full_Path", []):
        path_val = fp.get("Path") if isinstance(fp, dict) else fp
        if path_val:
            triples.append(_t(eid, "full-path", str(path_val)))

    return triples


def extract_lolbas_triples(repo_dir: str) -> Iterator[Triple]:
    repo_path = Path(repo_dir)
    yml_dirs = ["yml/OSBinaries", "yml/OtherMSBinaries", "yml/OSLibraries", "yml/OSScripts"]

    yaml_files = []
    for yd in yml_dirs:
        d = repo_path / yd
        if d.exists():
            yaml_files.extend(d.rglob("*.yml"))

    logger.info("Found %d LOLBAS YAML files", len(yaml_files))

    for yaml_file in yaml_files:
        try:
            with open(yaml_file) as f:
                data = yaml.safe_load(f)
            if data and isinstance(data, dict):
                yield from _binary_triples(data)
        except (yaml.YAMLError, KeyError, ValueError) as e:
            logger.warning("Failed to parse %s: %s", yaml_file, e)


if __name__ == "__main__":
    import argparse

    from common import write_triples_streaming

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description="LOLBAS -> KG Triples (Parquet)")
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument("--cache-dir", type=str, default=None)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    path = download_lolbas(args.cache_dir)
    write_triples_streaming(extract_lolbas_triples(path), args.output_dir / "lolbas.parquet")
