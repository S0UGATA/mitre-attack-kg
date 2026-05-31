"""Tests for generate_neighborhoods.py."""

import json
from pathlib import Path

import duckdb
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from generate_neighborhoods import (
    _slugify,
    entity_neighborhood,
    generate_neighborhoods,
    top_connected_entities,
)


def _write_parquet(tmp_path: Path) -> Path:
    # A tiny synthetic KG where T1059 is the hub:
    #   T1059 - subtechnique-of -> T1059.001, T1059.002 (ids)
    #   G0016 - uses            -> T1059                (id)
    #   T1059 - name            -> "Command and Scripting Interpreter" (string)
    #   T1059 - platform        -> "Windows"            (enum, junk-filtered terms excluded)
    #   CVE-2024-1 - mitigates  -> T1059                (id)
    rows = [
        ("T1059", "rdf:type", "Technique", "attack", "enum", ""),
        ("T1059", "name", "Command and Scripting Interpreter", "attack", "string", ""),
        ("T1059", "platform", "Windows", "attack", "enum", ""),
        ("T1059.001", "subtechnique-of", "T1059", "attack", "id", ""),
        ("T1059.002", "subtechnique-of", "T1059", "attack", "id", ""),
        ("G0016", "uses", "T1059", "attack", "id", ""),
        ("G0016", "rdf:type", "Group", "attack", "enum", ""),
        ("CVE-2024-1", "mitigates", "T1059", "cve", "id", ""),
        ("CVE-2024-1", "rdf:type", "Vulnerability", "cve", "enum", ""),
        # Junk entity that must be filtered out of top-N.
        ("none", "rdf:type", "Other", "cve", "enum", ""),
    ]
    df = pd.DataFrame(
        rows,
        columns=["subject", "predicate", "object", "source", "object_type", "meta"],
    )
    path = tmp_path / "tiny.parquet"
    pq.write_table(pa.Table.from_pandas(df, preserve_index=False), path)
    return path


def test_slugify_keeps_safe_chars_and_escapes_others():
    assert _slugify("T1059") == "T1059"
    assert _slugify("T1059.001") == "T1059.001"
    assert _slugify("CVE-2024-1234") == "CVE-2024-1234"
    # ':' and '/' must be escaped (filesystem / URL safety)
    assert _slugify("cpe:2.3:a:apache:httpd:*") == "cpe_3a2.3_3aa_3aapache_3ahttpd_3a_2a"
    # Distinct entities never collide
    assert _slugify("a/b") != _slugify("a_b")


def test_top_connected_entities_filters_junk(tmp_path):
    parquet = _write_parquet(tmp_path)
    con = duckdb.connect()
    con.execute(f"CREATE VIEW kg AS SELECT * FROM read_parquet('{parquet}')")
    top = top_connected_entities(con, top_n=5)
    # T1059 must rank first (4 subject + 3 id-typed object refs).
    assert top[0] == "T1059"
    # Junk entity 'none' must be excluded even though it appears as a subject.
    assert "none" not in top


def test_entity_neighborhood_shape_and_limit(tmp_path):
    parquet = _write_parquet(tmp_path)
    con = duckdb.connect()
    con.execute(f"CREATE VIEW kg AS SELECT * FROM read_parquet('{parquet}')")
    triples = entity_neighborhood(con, "T1059", depth=2, limit=500)
    # All Triple keys present, matching the viz interface.
    expected_keys = {"subject", "predicate", "object", "source", "object_type", "object_canonical"}
    assert all(set(t.keys()) == expected_keys for t in triples)
    # Hub neighborhood pulls every connected triple in this tiny KG.
    subjects = {t["subject"] for t in triples}
    assert {"T1059", "T1059.001", "T1059.002", "G0016", "CVE-2024-1"} <= subjects
    # object_canonical lower-cases literals, leaves id-typed objects untouched.
    by_pred = {(t["subject"], t["predicate"]): t for t in triples}
    assert by_pred[("T1059", "name")]["object_canonical"] == "command and scripting interpreter"
    assert by_pred[("T1059.001", "subtechnique-of")]["object_canonical"] == "T1059"


def test_entity_neighborhood_respects_limit(tmp_path):
    parquet = _write_parquet(tmp_path)
    con = duckdb.connect()
    con.execute(f"CREATE VIEW kg AS SELECT * FROM read_parquet('{parquet}')")
    triples = entity_neighborhood(con, "T1059", depth=2, limit=2)
    assert len(triples) <= 2


def test_generate_neighborhoods_writes_files_and_index(tmp_path):
    parquet = _write_parquet(tmp_path)
    out = tmp_path / "neighborhoods"
    index = generate_neighborhoods(parquet, out, top_n=3, depth=2, limit=500)

    # index.json structure
    assert index["source"] == "tiny.parquet"
    assert len(index["fingerprint"]) == 16
    assert index["depth"] == 2
    assert index["limit"] == 500
    assert index["count"] == len(index["entities"]) <= 3
    on_disk = json.loads((out / "index.json").read_text())
    assert on_disk == index

    # Each listed entity has a matching JSON whose content is a triple list.
    expected_keys = {"subject", "predicate", "object", "source", "object_type", "object_canonical"}
    for entry in index["entities"]:
        triples = json.loads((out / entry["file"]).read_text())
        assert isinstance(triples, list)
        assert len(triples) == entry["triples"]
        if triples:
            assert set(triples[0].keys()) == expected_keys
