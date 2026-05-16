"""Generate dashboard statistics JSON from parquet knowledge-graph files.

Produces a *.stats.json file for each parquet, containing pre-computed
aggregates consumed by the security-kg-viz Dashboard. This avoids heavy
DuckDB-WASM queries on every page load.

Usage:
    python src/generate_stats.py                                  # all parquets → stats/
    python src/generate_stats.py --output-dir /path/to/dir        # custom parquet dir
    python src/generate_stats.py --files cve.parquet ghsa.parquet  # subset only
"""

import argparse
import json
import logging
import time
from datetime import UTC, datetime
from pathlib import Path

import duckdb

from common import PROJECT_ROOT

logger = logging.getLogger(__name__)

KNOWN_FILES = [
    "combined.parquet",
    "attack-all.parquet",
    "enterprise.parquet",
    "mobile.parquet",
    "ics.parquet",
    "atlas.parquet",
    "capec.parquet",
    "car.parquet",
    "cpe.parquet",
    "cve.parquet",
    "cwe.parquet",
    "d3fend.parquet",
    "engage.parquet",
    "epss.parquet",
    "exploitdb.parquet",
    "ghsa.parquet",
    "kev.parquet",
    "sigma.parquet",
    "misp_galaxy.parquet",
    "vulnrichment.parquet",
    "lolbas.parquet",
    "loldrivers.parquet",
    "atomic.parquet",
    "nist_800_53.parquet",
    "nuclei.parquet",
    "euvd.parquet",
    "osv.parquet",
]

# Maps parquet filenames to source IDs used by the viz app.
# Files not listed here are skipped when building sourceDetails.
# ATT&CK children (enterprise, mobile, ics) are nested under attack-all.
_ATTACK_SOURCE_IDS = {
    "attack-all.parquet": "attack",
    "enterprise.parquet": "attack/enterprise",
    "mobile.parquet": "attack/mobile",
    "ics.parquet": "attack/ics",
}
FILE_TO_SOURCE_ID: dict[str, str] = {
    **{f: f.replace(".parquet", "") for f in KNOWN_FILES if f != "combined.parquet"},
    **_ATTACK_SOURCE_IDS,
}


MULTI_SOURCE_FILES = {"combined.parquet", "attack-all.parquet"}


def generate_stats(parquet_path: Path) -> dict:
    """Run aggregation queries against a parquet file and return a stats dict."""
    con = duckdb.connect()
    con.execute(f"CREATE VIEW kg AS SELECT * FROM read_parquet('{parquet_path}')")

    # Query 1: basic counts
    row = con.execute(
        """
        SELECT COUNT(*) AS total,
               COUNT(DISTINCT subject) AS subjects,
               COUNT(DISTINCT object) AS objects,
               COUNT(DISTINCT predicate) AS predicates
        FROM kg
        """
    ).fetchone()
    total_triples = row[0]
    unique_subjects = row[1]
    unique_objects = row[2]
    unique_predicates = row[3]

    # Query 2: top 25 predicates
    pred_rows = con.execute(
        "SELECT predicate, COUNT(*) AS cnt FROM kg GROUP BY predicate ORDER BY cnt DESC LIMIT 25"
    ).fetchall()
    top_predicates = [{"predicate": r[0], "count": r[1]} for r in pred_rows]

    # Query 3: source distribution (from the source column directly)
    dist_rows = con.execute(
        "SELECT source, COUNT(*) AS cnt FROM kg GROUP BY source ORDER BY cnt DESC"
    ).fetchall()
    by_source = [{"source": r[0], "count": r[1]} for r in dist_rows]

    # Query 4: cross-source links — only meaningful for multi-source files
    cross_source_links = []
    if parquet_path.name in MULTI_SOURCE_FILES:
        cross_rows = con.execute(
            """
            WITH obj_sources AS (
                SELECT DISTINCT subject AS id, source FROM kg
            ),
            id_refs AS (
                SELECT source, predicate, object FROM kg WHERE object_type = 'id'
            )
            SELECT ir.source AS src, os.source AS dst, ir.predicate, COUNT(*) AS cnt
            FROM id_refs ir
            JOIN obj_sources os ON ir.object = os.id
            WHERE ir.source != os.source
            GROUP BY ir.source, os.source, ir.predicate
            QUALIFY ROW_NUMBER() OVER (
                PARTITION BY ir.source, os.source ORDER BY COUNT(*) DESC
            ) = 1
            ORDER BY cnt DESC
            """
        ).fetchall()
        cross_source_links = [
            {"from": r[0], "to": r[1], "count": r[3], "predicate": r[2]} for r in cross_rows
        ]

    # Query 5: top 15 connected entities (filtered junk)
    entity_rows = con.execute(
        """
        SELECT entity, SUM(cnt) AS total FROM (
            SELECT subject AS entity, COUNT(*) AS cnt FROM kg GROUP BY subject
            UNION ALL
            SELECT object AS entity, COUNT(*) AS cnt FROM kg GROUP BY object
        )
        WHERE entity IS NOT NULL
          AND length(trim(entity)) > 1
          AND lower(trim(entity)) NOT IN
              ('no', 'none', 'n/a', 'na', '-', '--', 'null', 'unknown', 'other', 'true', 'false')
        GROUP BY entity
        ORDER BY total DESC
        LIMIT 15
        """
    ).fetchall()
    top_connected_entities = [{"entity": r[0], "count": r[1]} for r in entity_rows]

    con.close()

    return {
        "totalTriples": total_triples,
        "uniqueSubjects": unique_subjects,
        "uniqueObjects": unique_objects,
        "uniquePredicates": unique_predicates,
        "bySource": by_source,
        "topPredicates": top_predicates,
        "topConnectedEntities": top_connected_entities,
        "crossSourceLinks": cross_source_links,
        "generatedAt": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Generate dashboard statistics JSON from parquet KG files"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=PROJECT_ROOT / "output",
        help="Directory containing parquet files (default: output/)",
    )
    parser.add_argument(
        "--stats-dir",
        type=Path,
        default=PROJECT_ROOT / "hf_dataset" / ".stats",
        help="Directory to write stats JSON files (default: hf_dataset/.stats/)",
    )
    parser.add_argument(
        "--files",
        nargs="+",
        default=None,
        help="Specific parquet filenames to process (default: all known files)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [stats] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    generate_all_stats(args.output_dir, args.stats_dir, args.files)


def generate_all_stats(
    output_dir: Path,
    stats_dir: Path | None = None,
    files: list[str] | None = None,
) -> int:
    """Generate stats JSON for parquet files. Returns number of files processed."""
    if stats_dir is None:
        stats_dir = PROJECT_ROOT / "hf_dataset" / ".stats"
    filenames = files if files else KNOWN_FILES
    stats_dir.mkdir(parents=True, exist_ok=True)
    generated = 0
    source_details: dict[str, dict] = {}

    for filename in filenames:
        parquet_path = output_dir / filename
        if not parquet_path.exists():
            logger.warning("Skipping %s (not found)", parquet_path)
            continue

        t0 = time.monotonic()
        logger.info("Generating stats for %s", filename)
        stats = generate_stats(parquet_path)
        stats_path = stats_dir / filename.replace(".parquet", ".stats.json")
        stats_path.write_text(json.dumps(stats, indent=2) + "\n")
        elapsed = time.monotonic() - t0
        logger.info("Wrote %s (%d triples, %.1fs)", stats_path.name, stats["totalTriples"], elapsed)
        generated += 1

        # Collect per-source details for the combined stats
        source_id = FILE_TO_SOURCE_ID.get(filename)
        if source_id:
            source_details[source_id] = {
                "triples": stats["totalTriples"],
                "entities": stats["uniqueSubjects"],
                "predicates": stats["uniquePredicates"],
            }

    # Inject sourceDetails into the combined stats file
    combined_path = stats_dir / "combined.stats.json"
    if source_details and combined_path.exists():
        combined = json.loads(combined_path.read_text())
        combined["sourceDetails"] = source_details
        combined_path.write_text(json.dumps(combined, indent=2) + "\n")
        logger.info("Added sourceDetails (%d sources) to combined.stats.json", len(source_details))

    logger.info("Generated stats for %d/%d files", generated, len(filenames))
    return generated


if __name__ == "__main__":
    main()
