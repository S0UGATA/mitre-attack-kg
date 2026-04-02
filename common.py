"""Shared utilities for knowledge-graph triple converters."""

import logging
import tempfile
from pathlib import Path
from xml.etree import ElementTree as ET

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Download helper
# ---------------------------------------------------------------------------


def download_file(url: str, filename: str, cache_dir: str | None = None) -> Path:
    """Download a file with caching. Returns the local path."""
    if cache_dir:
        path = Path(cache_dir) / filename
        path.parent.mkdir(parents=True, exist_ok=True)
    else:
        path = Path(tempfile.gettempdir()) / filename

    if path.exists():
        logger.info("Using cached %s", path)
        return path

    logger.info("Downloading %s ...", url)
    resp = requests.get(url, timeout=120)
    resp.raise_for_status()
    path.write_bytes(resp.content)
    logger.info("Saved %s (%d bytes)", path, len(resp.content))
    return path


# ---------------------------------------------------------------------------
# XML helper
# ---------------------------------------------------------------------------


def xml_text(el: ET.Element | None) -> str:
    """Recursively extract all text from an XML element (strips xhtml markup)."""
    if el is None:
        return ""
    return "".join(el.itertext()).strip()


# ---------------------------------------------------------------------------
# Shared relationship predicates (Nature attribute → predicate name)
# ---------------------------------------------------------------------------

RELATION_PREDICATES = {
    "ChildOf": "child-of",
    "ParentOf": "parent-of",
    "CanPrecede": "can-precede",
    "CanFollow": "can-follow",
    "PeerOf": "peer-of",
    "CanAlsoBe": "can-also-be",
    "Requires": "requires",
    "StartsWith": "starts-with",
}


# ---------------------------------------------------------------------------
# Parquet output
# ---------------------------------------------------------------------------

PARQUET_SCHEMA = pa.schema(
    [
        pa.field("subject", pa.string()),
        pa.field("predicate", pa.string()),
        pa.field("object", pa.string()),
    ]
)

PARQUET_FORMATS = {
    "v1": {"version": "1.0", "compression": "gzip"},
    "v2": {"version": "2.6", "compression": "snappy"},
}


def triples_to_dataframe(triples: list[tuple[str, str, str]]) -> pd.DataFrame:
    """Convert list of (subject, predicate, object) tuples to DataFrame."""
    return pd.DataFrame(triples, columns=["subject", "predicate", "object"])


def write_parquet(df: pd.DataFrame, path: Path, parquet_format: str = "v2") -> None:
    """Write a DataFrame of triples to a Parquet file."""
    pq_opts = PARQUET_FORMATS[parquet_format]
    table = pa.table(
        {"subject": df["subject"], "predicate": df["predicate"], "object": df["object"]},
        schema=PARQUET_SCHEMA,
    )
    pq.write_table(table, path, **pq_opts)
    logger.info("Wrote %s (%d triples, format=%s)", path, len(df), parquet_format)
