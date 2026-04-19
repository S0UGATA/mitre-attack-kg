"""Graph traversals on security-kg using DuckDB recursive CTEs.

Demonstrates that SPO triples in Parquet support real graph queries — multi-hop
traversals, hierarchy walks, and cross-source chain analysis — without a graph
database.

Usage:
    python examples/graph_traversals.py                          # all queries
    python examples/graph_traversals.py --query attack-path      # single query
    python examples/graph_traversals.py --parquet output/combined.parquet
    python examples/graph_traversals.py --list                   # list queries

Requires: pip install duckdb  (already in requirements.txt)
"""

import argparse
import textwrap
from pathlib import Path

import duckdb

PARQUET_DEFAULT = Path("output/combined.parquet")


def _banner(title: str) -> None:
    width = 78
    print(f"\n{'─' * width}")
    print(f"  {title}")
    print(f"{'─' * width}")


def _run(con: duckdb.DuckDBPyConnection, sql: str, desc: str) -> None:
    _banner(desc)
    print(textwrap.dedent(sql).strip())
    print()
    try:
        df = con.sql(sql).fetchdf()
        if df.empty:
            print("  (no results — dataset may be too small for this traversal)")
        else:
            con.sql(sql).show()
    except duckdb.Error as e:
        print(f"  Query error: {e}")


# ── Query 1: Attack Path Expansion ──────────────────────────────────────


def attack_path(con: duckdb.DuckDBPyConnection, parquet: str) -> None:
    """Technique → CAPEC → CWE multi-hop chain via recursive CTE."""
    seed = con.sql(f"""
        SELECT object AS tid FROM '{parquet}'
        WHERE predicate = 'maps-to-technique' AND source = 'capec'
        LIMIT 1
    """).fetchone()
    if not seed:
        _banner("Attack Path Expansion")
        print("  (no maps-to-technique links found — need CAPEC + ATT&CK data)")
        return
    tid = seed[0]

    _run(
        con,
        f"""
        WITH RECURSIVE attack_chain AS (
            SELECT subject AS node,
                   predicate,
                   object AS next_node,
                   source,
                   1 AS depth,
                   subject || ' →[' || predicate || ']→ ' || object AS path
            FROM '{parquet}'
            WHERE object = '{tid}'
              AND predicate = 'maps-to-technique'

            UNION ALL

            SELECT t.subject,
                   t.predicate,
                   t.object,
                   t.source,
                   ac.depth + 1,
                   ac.path || ' →[' || t.predicate || ']→ ' || t.object
            FROM '{parquet}' t
            JOIN attack_chain ac ON t.subject = ac.node
            WHERE ac.depth < 4
              AND t.predicate IN ('related-weakness', 'related-attack-pattern',
                                  'affects-cpe', 'maps-to-technique')
              AND t.object != ac.next_node
        )
        SELECT depth, node AS from_node, predicate, next_node AS to_node, source, path
        FROM attack_chain
        ORDER BY depth, predicate
        LIMIT 50
        """,
        f"Attack Path Expansion: traverse from technique {tid} through CAPEC/CWE links",
    )


# ── Query 2: Defensive Coverage ─────────────────────────────────────────


def defense_coverage(con: duckdb.DuckDBPyConnection, parquet: str) -> None:
    """Find all defensive coverage (CAR, Sigma, D3FEND, Engage) for techniques."""
    _run(
        con,
        f"""
        WITH defended_techniques AS (
            SELECT t.object AS technique_id,
                   t.subject AS defense_id,
                   t.predicate AS defense_type,
                   t.source AS defense_source,
                   n.object AS defense_name
            FROM '{parquet}' t
            LEFT JOIN '{parquet}' n
              ON n.subject = t.subject AND n.predicate = 'name'
            WHERE t.predicate IN ('detects-technique', 'detects',
                                  'mitigates', 'engages-technique')
        )
        SELECT technique_id,
               tn.object AS technique_name,
               defense_source,
               defense_type,
               defense_id,
               defense_name
        FROM defended_techniques dt
        LEFT JOIN '{parquet}' tn
          ON tn.subject = dt.technique_id AND tn.predicate = 'name'
          AND tn.source = 'attack'
        ORDER BY technique_id, defense_source
        LIMIT 50
        """,
        "Defensive Coverage: detections/mitigations mapped to ATT&CK techniques",
    )


# ── Query 3: CWE Hierarchy Walk ─────────────────────────────────────────


def cwe_hierarchy(con: duckdb.DuckDBPyConnection, parquet: str) -> None:
    """Walk the CWE child-of hierarchy upward using recursive CTE."""
    seed = con.sql(f"""
        SELECT subject FROM '{parquet}'
        WHERE predicate = 'child-of' AND source = 'cwe'
        ORDER BY subject
        LIMIT 1
    """).fetchone()
    if not seed:
        _banner("CWE Hierarchy Walk")
        print("  (no child-of links found — need CWE data)")
        return
    cwe_id = seed[0]

    _run(
        con,
        f"""
        WITH RECURSIVE ancestry AS (
            SELECT subject AS cwe_id,
                   object AS parent_id,
                   1 AS depth,
                   subject AS path
            FROM '{parquet}'
            WHERE subject = '{cwe_id}'
              AND predicate = 'child-of'
              AND source = 'cwe'

            UNION ALL

            SELECT a.parent_id,
                   t.object,
                   a.depth + 1,
                   a.path || ' → ' || a.parent_id
            FROM '{parquet}' t
            JOIN ancestry a ON t.subject = a.parent_id
            WHERE t.predicate = 'child-of'
              AND t.source = 'cwe'
              AND a.depth < 10
        )
        SELECT a.cwe_id,
               a.parent_id,
               a.depth,
               n.object AS parent_name,
               a.path || ' → ' || a.parent_id AS full_path
        FROM ancestry a
        LEFT JOIN '{parquet}' n
          ON n.subject = a.parent_id AND n.predicate = 'name' AND n.source = 'cwe'
        ORDER BY depth
        """,
        f"CWE Hierarchy Walk: {cwe_id} → ancestors up to root pillar",
    )


# ── Query 4: Vulnerability Risk Profile ─────────────────────────────────


def vuln_risk_profile(con: duckdb.DuckDBPyConnection, parquet: str) -> None:
    """Multi-source risk profile for a CVE: EPSS + KEV + CWE + exploits."""
    seed = con.sql(f"""
        SELECT subject FROM '{parquet}'
        WHERE predicate = 'epss-score' AND subject LIKE 'CVE-%'
          AND CAST(object AS DOUBLE) > 0.5
        ORDER BY CAST(object AS DOUBLE) DESC
        LIMIT 1
    """).fetchone()
    if not seed:
        seed = con.sql(f"""
            SELECT subject FROM '{parquet}'
            WHERE predicate = 'epss-score' LIMIT 1
        """).fetchone()
    if not seed:
        _banner("Vulnerability Risk Profile")
        print("  (no CVEs with EPSS scores found)")
        return
    cve_id = seed[0]

    _run(
        con,
        f"""
        SELECT subject AS cve_id, source, predicate, object AS value
        FROM '{parquet}'
        WHERE subject = '{cve_id}'
          AND predicate IN (
            'name', 'description', 'cvss-base-score', 'cvss-severity',
            'epss-score', 'epss-percentile',
            'kev-date-added', 'kev-ransomware-use', 'kev-name',
            'related-weakness', 'affects-cpe',
            'exploits-cve', 'related-cve',
            'ssvc-exploitation', 'ssvc-automatable', 'ssvc-technical-impact'
          )
        ORDER BY source, predicate
        """,
        f"Vulnerability Risk Profile: {cve_id} across all sources",
    )


# ── Query 5: Exploit → Defense Chain ────────────────────────────────────


def exploit_to_defense(con: duckdb.DuckDBPyConnection, parquet: str) -> None:
    """Trace from a public exploit through CVE → CWE → CAPEC → technique → defenses."""
    _run(
        con,
        f"""
        WITH exploited_cves AS (
            SELECT e.subject AS exploit_id,
                   e.object AS cve_id
            FROM '{parquet}' e
            WHERE e.predicate = 'exploits-cve'
              AND e.source = 'exploitdb'
            LIMIT 10
        ),
        cve_to_cwe AS (
            SELECT ec.exploit_id, ec.cve_id,
                   t.object AS cwe_id
            FROM exploited_cves ec
            JOIN '{parquet}' t
              ON t.subject = ec.cve_id AND t.predicate = 'related-weakness'
        ),
        cwe_to_capec AS (
            SELECT cc.exploit_id, cc.cve_id, cc.cwe_id,
                   t.object AS capec_id
            FROM cve_to_cwe cc
            JOIN '{parquet}' t
              ON t.subject = cc.cwe_id AND t.predicate = 'related-attack-pattern'
        ),
        capec_to_technique AS (
            SELECT ct.exploit_id, ct.cve_id, ct.cwe_id, ct.capec_id,
                   t.object AS technique_id
            FROM cwe_to_capec ct
            JOIN '{parquet}' t
              ON t.subject = ct.capec_id AND t.predicate = 'maps-to-technique'
        ),
        technique_defenses AS (
            SELECT ctt.exploit_id, ctt.cve_id, ctt.cwe_id,
                   ctt.capec_id, ctt.technique_id,
                   d.subject AS defense_id,
                   d.predicate AS defense_type,
                   d.source AS defense_source
            FROM capec_to_technique ctt
            JOIN '{parquet}' d
              ON d.object = ctt.technique_id
              AND d.predicate IN ('detects-technique', 'mitigates',
                                  'engages-technique')
        )
        SELECT exploit_id,
               exploit_id || ' → ' || cve_id || ' → ' || cwe_id
                 || ' → ' || capec_id || ' → ' || technique_id AS chain,
               defense_source, defense_type, defense_id
        FROM technique_defenses
        ORDER BY exploit_id, technique_id
        LIMIT 50
        """,
        "Exploit → CVE → CWE → CAPEC → ATT&CK Technique → Defenses (5-hop)",
    )


# ── Query 6: Threat Actor Reach ──────────────────────────────────────────


def threat_actor_reach(con: duckdb.DuckDBPyConnection, parquet: str) -> None:
    """MISP/ATT&CK threat actors → techniques → platforms."""
    _run(
        con,
        f"""
        WITH actor_techniques AS (
            SELECT subject AS actor_id, object AS technique_id
            FROM '{parquet}'
            WHERE predicate IN ('uses', 'related-attack-id')
              AND object LIKE 'T%'
        ),
        actor_info AS (
            SELECT act.actor_id,
                   n.object AS actor_name,
                   act.technique_id,
                   p.object AS platform
            FROM actor_techniques act
            LEFT JOIN '{parquet}' n
              ON n.subject = act.actor_id AND n.predicate = 'name'
            LEFT JOIN '{parquet}' p
              ON p.subject = act.technique_id AND p.predicate = 'platform'
        )
        SELECT COALESCE(actor_name, actor_id) AS actor,
               COUNT(DISTINCT technique_id) AS techniques,
               COUNT(DISTINCT platform) AS platforms,
               STRING_AGG(DISTINCT platform, ', ' ORDER BY platform) AS platform_list
        FROM actor_info
        WHERE platform IS NOT NULL
        GROUP BY COALESCE(actor_name, actor_id), actor_id
        ORDER BY techniques DESC
        LIMIT 20
        """,
        "Threat Actor Reach: actors → ATT&CK techniques → target platforms",
    )


# ── Query 7: Detection Gap Analysis ─────────────────────────────────────


def sigma_gap_analysis(con: duckdb.DuckDBPyConnection, parquet: str) -> None:
    """Techniques with CAR/Sigma detection vs those without."""
    _run(
        con,
        f"""
        WITH all_techniques AS (
            SELECT DISTINCT subject AS technique_id
            FROM '{parquet}'
            WHERE predicate = 'rdf:type' AND object = 'Technique'
              AND source = 'attack'
        ),
        detection_coverage AS (
            SELECT DISTINCT object AS technique_id, source AS detector
            FROM '{parquet}'
            WHERE predicate IN ('detects-technique', 'detects')
              AND source IN ('sigma', 'car')
        ),
        summary AS (
            SELECT techs.technique_id,
                   n.object AS technique_name,
                   STRING_AGG(DISTINCT dc.detector, ', ') AS covered_by,
                   CASE WHEN COUNT(dc.detector) = 0 THEN 'UNCOVERED'
                        ELSE 'covered' END AS status
            FROM all_techniques techs
            LEFT JOIN detection_coverage dc ON dc.technique_id = techs.technique_id
            LEFT JOIN '{parquet}' n
              ON n.subject = techs.technique_id AND n.predicate = 'name'
              AND n.source = 'attack'
            GROUP BY techs.technique_id, n.object
        )
        SELECT technique_id, technique_name, status, covered_by
        FROM summary
        ORDER BY status DESC, technique_id
        LIMIT 30
        """,
        "Detection Gap: ATT&CK techniques with vs without Sigma/CAR coverage",
    )


# ── Query 8: Cross-Source Graph Stats ────────────────────────────────────


def cross_source_stats(con: duckdb.DuckDBPyConnection, parquet: str) -> None:
    """Graph connectivity — relationship density across sources."""
    _run(
        con,
        f"""
        WITH id_links AS (
            SELECT predicate, source,
                   COUNT(*) AS link_count,
                   COUNT(DISTINCT subject) AS unique_subjects,
                   COUNT(DISTINCT object) AS unique_objects
            FROM '{parquet}'
            WHERE object_type = 'id'
            GROUP BY predicate, source
        )
        SELECT predicate,
               source,
               link_count,
               unique_subjects AS from_entities,
               unique_objects AS to_entities
        FROM id_links
        ORDER BY link_count DESC
        LIMIT 30
        """,
        "Graph Connectivity: cross-source relationship density",
    )


# ── Registry ─────────────────────────────────────────────────────────────

QUERIES: dict[str, tuple[callable, str]] = {
    "attack-path": (
        attack_path,
        "Technique → CAPEC → CWE multi-hop chain (recursive CTE)",
    ),
    "defense-coverage": (
        defense_coverage,
        "All detections/mitigations mapped to ATT&CK techniques",
    ),
    "cwe-hierarchy": (
        cwe_hierarchy,
        "Walk CWE hierarchy upward to root pillar (recursive CTE)",
    ),
    "vuln-risk": (
        vuln_risk_profile,
        "CVE risk profile across EPSS, KEV, CVSS, Vulnrichment",
    ),
    "exploit-to-defense": (
        exploit_to_defense,
        "Exploit → CVE → CWE → CAPEC → technique → defenses (5-hop)",
    ),
    "threat-actor": (
        threat_actor_reach,
        "Threat actors → ATT&CK techniques → target platforms",
    ),
    "sigma-gap": (
        sigma_gap_analysis,
        "ATT&CK techniques with vs without Sigma/CAR detection",
    ),
    "stats": (
        cross_source_stats,
        "Cross-source relationship density statistics",
    ),
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Graph traversals on security-kg using DuckDB recursive CTEs"
    )
    parser.add_argument(
        "--parquet",
        type=Path,
        default=PARQUET_DEFAULT,
        help=f"Path to combined.parquet (default: {PARQUET_DEFAULT})",
    )
    parser.add_argument(
        "--query",
        choices=list(QUERIES.keys()),
        help="Run a single query (default: all)",
    )
    parser.add_argument("--list", action="store_true", help="List available queries and exit")
    args = parser.parse_args()

    if args.list:
        print("Available queries:\n")
        for name, (_, desc) in QUERIES.items():
            print(f"  {name:20s}  {desc}")
        return

    if not args.parquet.exists():
        print(f"Parquet file not found: {args.parquet}")
        print("Run 'python src/convert.py' first, or specify --parquet path.")
        return

    con = duckdb.connect()

    if args.query:
        fn, _ = QUERIES[args.query]
        fn(con, str(args.parquet))
    else:
        for _name, (fn, _) in QUERIES.items():
            fn(con, str(args.parquet))

    con.close()


if __name__ == "__main__":
    main()
