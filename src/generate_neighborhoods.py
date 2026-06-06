"""Pre-compute neighborhood JSONs for the top-N most-connected entities.

For each of the top-N entities in a parquet knowledge-graph file we run a
multi-hop BFS (default depth=2, limit=500 triples) and write the result as
``<entity>.json`` — the same shape ``security-kg-viz`` already consumes from
``q.entityNeighborhood()`` (the ``Triple`` interface in
``src/lib/duckdb.ts``).

This lets the viz skip DuckDB-WASM + Parquet metadata + recursive-CTE work
for the most-clicked entities by fetching a static JSON from the HuggingFace
CDN. An ``index.json`` lists every entity that has a pre-computed file plus a
fingerprint of the source parquet so the viz can invalidate its cache.

Usage:
    python src/generate_neighborhoods.py                                  # combined.parquet
    python src/generate_neighborhoods.py --output-dir /path/to/parquet/dir
    python src/generate_neighborhoods.py --parquet enterprise.parquet
    python src/generate_neighborhoods.py --top-n 200 --depth 2 --limit 500
"""

import argparse
import hashlib
import json
import logging
import re
import time
from datetime import UTC, datetime
from pathlib import Path

import duckdb

from common import PROJECT_ROOT

logger = logging.getLogger(__name__)

# Mirrors the viz's defaults so a pre-computed file can be dropped straight
# into ``buildGraph()`` without re-querying.
DEFAULT_TOP_N = 200
DEFAULT_DEPTH = 2
DEFAULT_LIMIT = 500
DEFAULT_PARQUET = "combined.parquet"

# Junk-entity filter, kept in sync with generate_stats.topConnectedEntities so
# the same low-information IDs aren't pre-rendered.
_JUNK_LOWER = {
    "no",
    "none",
    "n/a",
    "na",
    "-",
    "--",
    "null",
    "unknown",
    "other",
    "true",
    "false",
}

# Slug character class: keep filenames portable on all OSes / HF storage and
# safe to drop into a URL path. Anything outside this set is hex-escaped so
# the mapping stays reversible and collision-free.
_SAFE_SLUG_RE = re.compile(r"[A-Za-z0-9._-]")


def _slugify(entity: str) -> str:
    """Return a filesystem- and URL-safe slug for ``entity``.

    Characters outside ``[A-Za-z0-9._-]`` are percent-encoded with their
    UTF-8 hex bytes (``_xx``) so distinct entities cannot collide.
    """
    out: list[str] = []
    for ch in entity:
        if _SAFE_SLUG_RE.match(ch):
            out.append(ch)
        else:
            for b in ch.encode("utf-8"):
                out.append(f"_{b:02x}")
    return "".join(out) or "_"


def _parquet_fingerprint(parquet_path: Path) -> str:
    """Return a short stable fingerprint (sha256, first 16 hex chars).

    Computed in a streaming fashion so multi-GB combined parquets don't
    require loading the whole file into memory.
    """
    h = hashlib.sha256()
    with parquet_path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def top_connected_entities(con: duckdb.DuckDBPyConnection, top_n: int) -> list[str]:
    """Return the IDs of the top-N entities by total edge count.

    Counts ``subject`` occurrences plus ``object`` occurrences when the
    object is an entity reference (``object_type = 'id'``). Mirrors the
    query suggested in the issue.
    """
    rows = con.execute(
        f"""
        SELECT entity, COUNT(*) AS edge_count
        FROM (
            SELECT subject AS entity FROM kg
            UNION ALL
            SELECT object  AS entity FROM kg WHERE object_type = 'id'
        )
        WHERE entity IS NOT NULL
          AND length(trim(entity)) > 1
          AND lower(trim(entity)) NOT IN ({", ".join("?" * len(_JUNK_LOWER))})
        GROUP BY entity
        ORDER BY edge_count DESC
        LIMIT ?
        """,
        [*sorted(_JUNK_LOWER), top_n],
    ).fetchall()
    return [r[0] for r in rows]


def _resolve_seed_entities(con: duckdb.DuckDBPyConnection, entity: str) -> list[str]:
    """Match how the viz resolves a search term to concrete IDs (ILIKE, cap 10)."""
    rows = con.execute(
        """
        SELECT DISTINCT id FROM (
            SELECT subject AS id FROM kg WHERE subject ILIKE ?
            UNION ALL
            SELECT object  AS id FROM kg WHERE object  ILIKE ?
        ) LIMIT 10
        """,
        [entity, entity],
    ).fetchall()
    ids = [r[0] for r in rows]
    return ids or [entity]


def _fetch_neighbors(con: duckdb.DuckDBPyConnection, ids: list[str], limit: int) -> list[tuple]:
    """Fetch up to ``limit`` triples touching any of ``ids`` as subject or object.

    Uses the same ``UNION ALL`` split the viz uses so DuckDB can prune
    row-groups independently for the subject and object filters.
    """
    placeholders = ", ".join("?" * len(ids))
    cols = "subject, predicate, object, source, object_type"
    return con.execute(
        f"""
        SELECT * FROM (
            (SELECT {cols} FROM kg WHERE subject IN ({placeholders}) LIMIT ?)
            UNION ALL
            (SELECT {cols} FROM kg WHERE object  IN ({placeholders}) LIMIT ?)
        )
        LIMIT ?
        """,
        [*ids, limit, *ids, limit, limit],
    ).fetchall()


def _to_triple(row: tuple) -> dict:
    """Convert a DuckDB row to the viz's ``Triple`` shape (incl. object_canonical)."""
    subject, predicate, obj, source, object_type = row
    canonical = obj if object_type == "id" else (obj or "").strip().lower()
    return {
        "subject": subject,
        "predicate": predicate,
        "object": obj,
        "source": source or "",
        "object_type": object_type or "",
        "object_canonical": canonical,
    }


def entity_neighborhood(
    con: duckdb.DuckDBPyConnection, entity: str, depth: int, limit: int
) -> list[dict]:
    """BFS multi-hop neighborhood, capped at ``limit`` triples.

    Mirrors ``traverseBFS`` in ``security-kg-viz/src/lib/duckdb.ts``: hops
    0..depth-1 expand, depth stops; the outer ``limit`` bounds total work
    regardless of graph degree.
    """
    seeds = _resolve_seed_entities(con, entity)
    triples: dict[str, dict] = {}
    frontier: set[str] = set(seeds)
    visited: set[str] = set()

    for _ in range(depth):
        if len(triples) >= limit:
            break
        new_ids = [i for i in frontier if i not in visited]
        if not new_ids:
            break
        visited.update(new_ids)

        rows = _fetch_neighbors(con, new_ids, limit - len(triples))
        next_frontier: set[str] = set()
        for row in rows:
            if len(triples) >= limit:
                break
            t = _to_triple(row)
            key = f"{t['subject']}\t{t['predicate']}\t{t['object']}"
            if key in triples:
                continue
            triples[key] = t
            if t["subject"] not in visited:
                next_frontier.add(t["subject"])
            if t["object"] not in visited:
                next_frontier.add(t["object"])
        frontier = next_frontier

    return list(triples.values())


def generate_neighborhoods(
    parquet_path: Path,
    output_dir: Path,
    top_n: int = DEFAULT_TOP_N,
    depth: int = DEFAULT_DEPTH,
    limit: int = DEFAULT_LIMIT,
) -> dict:
    """Generate ``<entity>.json`` files + ``index.json`` for ``parquet_path``.

    Returns the parsed ``index.json`` for callers / tests.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    con = duckdb.connect()
    con.execute(f"CREATE VIEW kg AS SELECT * FROM read_parquet('{parquet_path}')")

    entities = top_connected_entities(con, top_n)
    logger.info("Pre-computing neighborhoods for top %d entities", len(entities))

    fingerprint = _parquet_fingerprint(parquet_path)
    index_entries: list[dict] = []
    for entity in entities:
        slug = _slugify(entity)
        filename = f"{slug}.json"
        t0 = time.monotonic()
        triples = entity_neighborhood(con, entity, depth, limit)
        (output_dir / filename).write_text(json.dumps(triples, separators=(",", ":")))
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        index_entries.append({"entity": entity, "file": filename, "triples": len(triples)})
        logger.debug("%-30s -> %s (%d triples, %d ms)", entity, filename, len(triples), elapsed_ms)

    con.close()

    index = {
        "source": parquet_path.name,
        "fingerprint": fingerprint,
        "depth": depth,
        "limit": limit,
        "count": len(index_entries),
        "generatedAt": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "entities": index_entries,
    }
    (output_dir / "index.json").write_text(json.dumps(index, indent=2) + "\n")
    logger.info("Wrote %d neighborhood JSONs + index.json to %s", len(index_entries), output_dir)
    return index


def main():
    parser = argparse.ArgumentParser(
        description="Pre-compute neighborhood JSONs for the top-N most-connected entities"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=PROJECT_ROOT / "output",
        help="Directory containing parquet files (default: output/)",
    )
    parser.add_argument(
        "--neighborhoods-dir",
        type=Path,
        default=PROJECT_ROOT / "hf_dataset" / ".neighborhoods",
        help="Directory to write neighborhood JSONs (default: hf_dataset/.neighborhoods/)",
    )
    parser.add_argument(
        "--parquet",
        default=DEFAULT_PARQUET,
        help=f"Parquet filename to read from --output-dir (default: {DEFAULT_PARQUET})",
    )
    parser.add_argument("--top-n", type=int, default=DEFAULT_TOP_N)
    parser.add_argument("--depth", type=int, default=DEFAULT_DEPTH)
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [neighborhoods] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    parquet_path = args.output_dir / args.parquet
    if not parquet_path.exists():
        logger.warning("Parquet %s not found, nothing to do", parquet_path)
        return

    generate_neighborhoods(
        parquet_path,
        args.neighborhoods_dir,
        top_n=args.top_n,
        depth=args.depth,
        limit=args.limit,
    )


if __name__ == "__main__":
    main()
