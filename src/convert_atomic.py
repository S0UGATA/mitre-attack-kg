"""Atomic Red Team YAML -> Knowledge Graph SPO Triples."""

import logging
from collections.abc import Iterator
from pathlib import Path

import yaml

from common import SOURCE_DIR, Triple, download_github_zip, make_triple_fn, truncate_text

logger = logging.getLogger(__name__)

SOURCE = "atomic"


_t = make_triple_fn(SOURCE)


def download_atomic(cache_dir: str | None = None, *, force_download: bool = False) -> str:
    cache = Path(cache_dir) if cache_dir else SOURCE_DIR
    path = download_github_zip(
        "redcanaryco",
        "atomic-red-team",
        "atomic.zip",
        "master",
        cache,
        force_download=force_download,
    )
    return str(path)


def _test_triples(test: dict, technique_id: str) -> list[Triple]:
    guid = test.get("auto_generated_guid", "")
    if not guid:
        return []

    eid = str(guid)
    triples: list[Triple] = [
        _t(eid, "rdf:type", "AtomicTest"),
    ]

    name = test.get("name")
    if name:
        triples.append(_t(eid, "name", str(name)))

    desc = test.get("description")
    if desc:
        triples.append(_t(eid, "description", truncate_text(str(desc))))

    triples.append(_t(eid, "tests-technique", technique_id.upper()))

    for platform in test.get("supported_platforms", []):
        triples.append(_t(eid, "platform", str(platform)))

    executor = test.get("executor", {})
    if isinstance(executor, dict) and executor.get("name"):
        triples.append(_t(eid, "executor", str(executor["name"])))

    return triples


def extract_atomic_triples(
    repo_dir: str,
) -> Iterator[Triple]:
    repo_path = Path(repo_dir)

    atomics_dir = repo_path / "atomics"
    if not atomics_dir.exists():
        logger.warning("Atomic Red Team atomics/ directory not found in %s", repo_path)
        return

    yaml_files = sorted(atomics_dir.glob("T*/T*.yaml"))
    logger.info("Found %d Atomic Red Team YAML files", len(yaml_files))

    for yaml_file in yaml_files:
        try:
            with open(yaml_file) as f:
                data = yaml.safe_load(f)
            if not data or not isinstance(data, dict):
                continue

            technique_id = data.get("attack_technique", "")
            if not technique_id:
                continue

            for test in data.get("atomic_tests", []):
                if isinstance(test, dict):
                    yield from _test_triples(test, str(technique_id))

        except (yaml.YAMLError, KeyError, ValueError) as e:
            logger.warning("Failed to parse %s: %s", yaml_file, e)


if __name__ == "__main__":
    import argparse

    from common import write_triples_streaming

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    parser = argparse.ArgumentParser(description="Atomic Red Team -> KG Triples (Parquet)")
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument("--cache-dir", type=str, default=None)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    path = download_atomic(args.cache_dir)
    write_triples_streaming(extract_atomic_triples(path), args.output_dir / "atomic.parquet")
