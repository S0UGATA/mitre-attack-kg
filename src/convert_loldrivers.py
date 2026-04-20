"""LOLDrivers (Living Off The Land Drivers) YAML -> Knowledge Graph SPO Triples."""

import logging
from collections.abc import Iterator
from pathlib import Path

import yaml

from common import SOURCE_DIR, Triple, download_github_zip, make_triple_fn, meta_json

logger = logging.getLogger(__name__)

SOURCE = "loldrivers"


_t = make_triple_fn(SOURCE)


def download_loldrivers(cache_dir: str | None = None, *, force_download: bool = False) -> str:
    cache = Path(cache_dir) if cache_dir else SOURCE_DIR
    path = download_github_zip(
        "magicsword-io",
        "LOLDrivers",
        "loldrivers.zip",
        "main",
        cache,
        force_download=force_download,
    )
    return str(path)


def _driver_triples(data: dict) -> list[Triple]:
    driver_id = data.get("Id", "")
    if not driver_id:
        return []

    eid = str(driver_id)

    tags = data.get("Tags", [])
    name = str(tags[0]) if tags else ""

    entity_meta: dict = {}
    refs = data.get("Resources", [])
    if refs:
        ref_urls = [str(r) for r in refs if r]
        if ref_urls:
            entity_meta["references"] = ref_urls

    triples: list[Triple] = [
        _t(eid, "rdf:type", "LOLDriver", meta_json(entity_meta)),
    ]
    if name:
        triples.append(_t(eid, "name", name))

    category = data.get("Category", "")
    if category:
        triples.append(_t(eid, "category", str(category)))

    for cmd in data.get("Commands", []):
        if not isinstance(cmd, dict):
            continue
        usecase = cmd.get("Usecase")
        if usecase:
            triples.append(_t(eid, "usecase", str(usecase)))
        privs = cmd.get("Privileges")
        if privs:
            triples.append(_t(eid, "privileges", str(privs)))
        os_name = cmd.get("OperatingSystem")
        if os_name:
            triples.append(_t(eid, "platform", str(os_name)))

    mitre_id = data.get("MitreID")
    if mitre_id:
        triples.append(_t(eid, "maps-to-technique", str(mitre_id).upper()))

    for sample in data.get("KnownVulnerableSamples", []):
        if not isinstance(sample, dict):
            continue
        sha256 = sample.get("SHA256")
        if sha256:
            triples.append(_t(eid, "sha256", str(sha256)))
        sha1 = sample.get("SHA1")
        if sha1:
            triples.append(_t(eid, "sha1", str(sha1)))
        md5 = sample.get("MD5")
        if md5:
            triples.append(_t(eid, "md5", str(md5)))
        company = sample.get("Company")
        if company:
            triples.append(_t(eid, "vendor", str(company)))
        filename = sample.get("OriginalFilename") or sample.get("InternalName")
        if filename:
            triples.append(_t(eid, "product", str(filename)))

    return triples


def extract_loldrivers_triples(
    repo_dir: str,
) -> Iterator[Triple]:
    repo_path = Path(repo_dir)

    yaml_dir = repo_path / "yaml"
    if not yaml_dir.exists():
        logger.warning("LOLDrivers yaml/ directory not found in %s", repo_path)
        return

    yaml_files = list(yaml_dir.rglob("*.yaml"))
    logger.info("Found %d LOLDrivers YAML files", len(yaml_files))

    for yaml_file in yaml_files:
        try:
            with open(yaml_file) as f:
                data = yaml.safe_load(f)
            if data and isinstance(data, dict):
                yield from _driver_triples(data)
        except (yaml.YAMLError, KeyError, ValueError) as e:
            logger.warning("Failed to parse %s: %s", yaml_file, e)


if __name__ == "__main__":
    import argparse

    from common import write_triples_streaming

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description="LOLDrivers -> KG Triples (Parquet)")
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument("--cache-dir", type=str, default=None)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    path = download_loldrivers(args.cache_dir)
    write_triples_streaming(
        extract_loldrivers_triples(path), args.output_dir / "loldrivers.parquet"
    )
