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

# Source detection SQL — must stay in sync with detectSource() in
# security-kg-viz/src/lib/constants.ts and Dashboard.tsx SOURCE_CASE_SQL.
SOURCE_CASE_SQL = """
  CASE
    WHEN {col} LIKE 'T__%' AND regexp_matches({col}, '^T\\d+') THEN 'attack'
    WHEN {col} LIKE 'TA%' AND regexp_matches({col}, '^TA\\d+') THEN 'attack'
    WHEN {col} LIKE 'G%' AND regexp_matches({col}, '^G\\d+') THEN 'attack'
    WHEN {col} LIKE 'S%' AND regexp_matches({col}, '^S\\d+') THEN 'attack'
    WHEN {col} LIKE 'M%' AND regexp_matches({col}, '^M\\d+') THEN 'attack'
    WHEN {col} LIKE 'DS%' AND regexp_matches({col}, '^DS\\d+') THEN 'attack'
    WHEN regexp_matches({col}, '^C\\d{{4}}') THEN 'attack'
    WHEN {col} LIKE 'DC%' AND regexp_matches({col}, '^DC\\d+') THEN 'attack'
    WHEN {col} LIKE 'CAPEC-%' THEN 'capec'
    WHEN {col} LIKE 'CWE-%' THEN 'cwe'
    WHEN {col} LIKE 'CVE-%' THEN 'cve'
    WHEN {col} LIKE 'cpe:%' OR {col} LIKE 'CPE:%' THEN 'cpe'
    WHEN {col} LIKE 'D3-%' THEN 'd3fend'
    WHEN {col} LIKE 'AML.%' THEN 'atlas'
    WHEN {col} LIKE 'CAR-%' THEN 'car'
    WHEN regexp_matches({col}, '^E[AV][CV]\\d+') THEN 'engage'
    WHEN {col} LIKE 'DET%' AND regexp_matches({col}, '^DET\\d+') THEN 'engage'
    WHEN {col} LIKE 'GHSA-%' THEN 'ghsa'
    WHEN {col} LIKE 'EDB-%' THEN 'exploitdb'
    WHEN {col} LIKE 'misp:%' THEN 'misp_galaxy'
    WHEN regexp_matches({col},
      '^[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}$'
    ) THEN 'sigma'
    ELSE 'literal'
  END
"""

SUBJECT_SOURCE = SOURCE_CASE_SQL.format(col="subject")
OBJECT_SOURCE = SOURCE_CASE_SQL.format(col="object")


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

    # Query 3: source distribution + cross-source links (single scan with SOURCE_CASE_SQL)
    source_rows = con.execute(
        f"""
        WITH sourced AS (
            SELECT {SUBJECT_SOURCE} AS src, {OBJECT_SOURCE} AS dst, predicate
            FROM kg
        )
        SELECT 'dist' AS kind, source, NULL AS dst, NULL AS pred, SUM(cnt) AS cnt FROM (
            SELECT src AS source, COUNT(*) AS cnt FROM sourced GROUP BY src
            UNION ALL
            SELECT dst AS source, COUNT(*) AS cnt FROM sourced GROUP BY dst
        )
        WHERE source != 'literal'
        GROUP BY source
        UNION ALL
        SELECT 'cross' AS kind, src, dst, predicate, COUNT(*) AS cnt
        FROM sourced
        WHERE src != dst AND src != 'literal' AND dst != 'literal'
        GROUP BY src, dst, predicate
        QUALIFY ROW_NUMBER() OVER (PARTITION BY src, dst ORDER BY COUNT(*) DESC) = 1
        """
    ).fetchall()
    by_source = []
    cross_source_links = []
    for row in source_rows:
        if row[0] == "dist":
            by_source.append({"source": row[1], "count": row[4]})
        else:
            cross_source_links.append(
                {"from": row[1], "to": row[2], "count": row[4], "predicate": row[3]}
            )
    by_source.sort(key=lambda x: x["count"], reverse=True)
    cross_source_links.sort(key=lambda x: x["count"], reverse=True)
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
