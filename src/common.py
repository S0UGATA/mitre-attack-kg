"""Shared utilities for knowledge-graph triple converters."""

import gzip
import hashlib
import json
import logging
import os
import re
import shutil
import tarfile
import zipfile
from email.utils import parsedate_to_datetime
from pathlib import Path
from xml.etree import ElementTree as ET  # noqa: S405 — trusted MITRE data only

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default cache directory (project-local)
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

SOURCE_DIR = PROJECT_ROOT / "source"

# ---------------------------------------------------------------------------
# Download helpers
# ---------------------------------------------------------------------------


def _ts_from_http_date(date_str: str) -> str:
    """Convert an HTTP date header to a compact timestamp string (YYYYMMDD_HHMMSS)."""
    try:
        dt = parsedate_to_datetime(date_str)
        return dt.strftime("%Y%m%d_%H%M")
    except (ValueError, TypeError, IndexError):
        return ""


def _fingerprint_from_etag(etag: str) -> str:
    """Create a short filename-safe fingerprint from an ETag header value."""
    clean = etag.strip()
    if clean.startswith("W/"):
        clean = clean[2:]
    clean = clean.strip('"')
    if not clean:
        return ""
    return hashlib.sha256(clean.encode()).hexdigest()[:12]


def github_api_headers() -> dict[str, str]:
    """Build headers for GitHub API requests, including auth token if available."""
    headers = {"Accept": "application/vnd.github.v3+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


def _github_commit_sha(owner: str, repo: str, branch: str = "main") -> str:
    """Get the latest commit SHA (12-char prefix) for a GitHub repo branch.

    Provides a stable, deterministic fingerprint for GitHub-hosted repos,
    unlike the unstable ETag/Last-Modified headers on GitHub archive URLs.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{branch}"
    resp = requests.get(url, headers=github_api_headers(), timeout=30)
    resp.raise_for_status()
    return resp.json()["sha"][:12]


def _github_release_tag(owner: str, repo: str) -> str:
    """Get the latest release tag for a GitHub repo."""
    url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
    resp = requests.get(url, headers=github_api_headers(), timeout=30)
    resp.raise_for_status()
    return resp.json()["tag_name"]


# Regex to detect GitHub archive URLs and extract owner/repo/branch
_GITHUB_ARCHIVE_RE = re.compile(
    r"https?://github\.com/([^/]+)/([^/]+)/archive/refs/heads/(.+?)(?:\.zip|\.tar\.gz)$"
)


def _remote_version(url: str) -> str:
    """Return a version fingerprint from Last-Modified or ETag headers.

    Tries Last-Modified first (human-readable timestamp), then falls back
    to a hash of the ETag.  Returns empty string if neither is available.
    """
    try:
        head = requests.head(url, timeout=30, allow_redirects=True)
        lm = head.headers.get("Last-Modified", "")
        if lm:
            ts = _ts_from_http_date(lm)
            if ts:
                return ts
        etag = head.headers.get("ETag", "")
        if etag:
            return _fingerprint_from_etag(etag)
    except (requests.RequestException, OSError):
        pass
    return ""


def _cleanup_old_versions(cache: Path, stem: str, suffix: str, keep: Path) -> None:
    """Remove old versioned files, keeping only the specified path."""
    for old in cache.glob(f"{stem}_*{suffix}"):
        if old != keep:
            try:
                old.unlink()
                logger.info("Cleaned up old cached file %s", old)
            except OSError:
                pass


def download_file(
    url: str,
    filename: str,
    cache_dir: str | None = None,
    *,
    version_override: str | None = None,
) -> Path:
    """Download a file with version-based caching. Returns the local path.

    Files are saved as ``<stem>_<version><suffix>`` where *version* comes from
    *version_override* (if given), the source's ``Last-Modified`` header
    (preferred), or a hash of its ``ETag``.  If a file with the same version
    already exists locally, the download is skipped.

    When neither header is available and no override is given, the file is
    always re-downloaded to avoid serving stale data indefinitely.

    Old versions of the same file are automatically cleaned up.
    """
    cache = Path(cache_dir) if cache_dir else SOURCE_DIR
    cache.mkdir(parents=True, exist_ok=True)

    stem = Path(filename).stem
    suffix = Path(filename).suffix

    version = version_override or _remote_version(url)

    if version:
        versioned_filename = f"{stem}_{version}{suffix}"
        versioned_path = cache / versioned_filename
        if versioned_path.exists():
            logger.info("Using cached %s (up-to-date)", versioned_path)
            return versioned_path
    else:
        # No version info — will always re-download
        versioned_path = cache / filename

    logger.info("Downloading %s ...", url)
    resp = requests.get(url, timeout=600, stream=True)
    resp.raise_for_status()
    with open(versioned_path, "wb") as f:
        for chunk in resp.iter_content(chunk_size=8192):
            f.write(chunk)
    size = versioned_path.stat().st_size
    logger.info("Saved %s (%d bytes)", versioned_path, size)

    # Clean up older versions
    if version:
        _cleanup_old_versions(cache, stem, suffix, versioned_path)

    return versioned_path


def download_gzip(url: str, filename: str, cache_dir: str | None = None) -> Path:
    """Download a gzip-compressed file and decompress it. Returns path to decompressed file."""
    gz_path = download_file(url, filename + ".gz", cache_dir)
    out_path = gz_path.with_suffix("")  # strip .gz
    if out_path.exists():
        logger.info("Using cached decompressed %s", out_path)
        return out_path
    logger.info("Decompressing %s ...", gz_path)
    with gzip.open(gz_path, "rb") as f_in, open(out_path, "wb") as f_out:
        f_out.write(f_in.read())
    logger.info("Decompressed %s (%d bytes)", out_path, out_path.stat().st_size)
    return out_path


def download_tar_gz(url: str, filename: str, cache_dir: str | None = None) -> Path:
    """Download a tar.gz and extract. Returns path to the extraction directory."""
    tgz_path = download_file(url, filename, cache_dir)
    extract_dir = tgz_path.parent / tgz_path.stem.replace(".tar", "")
    if extract_dir.exists() and any(extract_dir.iterdir()):
        logger.info("Using cached extraction %s", extract_dir)
        return extract_dir
    extract_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Extracting %s ...", tgz_path)
    with tarfile.open(tgz_path, "r:gz") as tar:
        tar.extractall(extract_dir, filter="data")
    logger.info("Extracted to %s", extract_dir)
    return extract_dir


def safe_zip_extract(zip_path: Path, extract_dir: Path) -> None:
    """Extract a ZIP file, rejecting entries with path traversal attempts."""
    resolved = extract_dir.resolve()
    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.namelist():
            target = (extract_dir / member).resolve()
            if not str(target).startswith(str(resolved)):
                raise ValueError(f"Zip entry {member!r} would escape extraction directory")
        for info in zf.infolist():
            zf.extract(info, extract_dir)
            extracted = extract_dir / info.filename
            if info.is_dir():
                os.chmod(extracted, 0o755)
            else:
                os.chmod(extracted, 0o644)


def download_zip(url: str, filename: str, cache_dir: str | None = None) -> Path:
    """Download a ZIP and extract. Returns path to the extraction directory."""
    zip_path = download_file(url, filename, cache_dir)
    extract_dir = zip_path.parent / zip_path.stem
    if extract_dir.exists() and any(extract_dir.iterdir()):
        logger.info("Using cached extraction %s", extract_dir)
        return extract_dir
    extract_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Extracting %s ...", zip_path)
    safe_zip_extract(zip_path, extract_dir)
    logger.info("Extracted to %s", extract_dir)
    return extract_dir


def download_github_zip(
    owner: str,
    repo: str,
    filename: str,
    branch: str = "main",
    cache_dir: str | None = None,
) -> Path:
    """Download a GitHub repo archive ZIP using a commit-SHA fingerprint.

    Unlike ``download_zip`` with a GitHub archive URL, this uses the GitHub
    Commits API to get a stable version fingerprint (commit SHA), avoiding
    false cache misses caused by unstable ETag / Last-Modified headers on
    GitHub's archive CDN.
    """
    url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.zip"
    try:
        sha = _github_commit_sha(owner, repo, branch)
        logger.info("GitHub %s/%s@%s commit SHA: %s", owner, repo, branch, sha)
    except (requests.RequestException, KeyError, OSError) as exc:
        logger.warning(
            "Failed to get commit SHA for %s/%s (%s), falling back to HTTP headers",
            owner,
            repo,
            exc,
        )
        sha = None

    zip_path = download_file(url, filename, cache_dir, version_override=sha)
    extract_dir = zip_path.parent / zip_path.stem
    if extract_dir.exists() and any(extract_dir.iterdir()):
        logger.info("Using cached extraction %s", extract_dir)
        return extract_dir

    # Clean up old extraction dirs for previous versions
    stem = Path(filename).stem
    for old_dir in zip_path.parent.glob(f"{stem}_*"):
        if old_dir.is_dir() and old_dir != extract_dir:
            try:
                shutil.rmtree(old_dir)
                logger.info("Cleaned up old extraction dir %s", old_dir)
            except OSError:
                pass

    extract_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Extracting %s ...", zip_path)
    safe_zip_extract(zip_path, extract_dir)
    logger.info("Extracted to %s", extract_dir)
    return extract_dir


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
    "CanAlsoBe": "can-also-be",
    "CanFollow": "can-follow",
    "CanPrecede": "can-precede",
    "ChildOf": "child-of",
    "ParentOf": "parent-of",
    "PeerOf": "peer-of",
    "Requires": "requires",
    "StartsWith": "starts-with",
}


# ---------------------------------------------------------------------------
# Object type classification for predicates
# ---------------------------------------------------------------------------

PREDICATE_TYPES: dict[str, str] = {
    # boolean
    "deprecated": "boolean",
    "is-subtechnique": "boolean",
    "revoked": "boolean",
    "verified": "boolean",
    # date
    "created": "date",
    "date": "date",
    "date-modified": "date",
    "date-published": "date",
    "date-updated": "date",
    "kev-date-added": "date",
    "kev-due-date": "date",
    "modified": "date",
    "submission-date": "date",
    # enum
    "abstraction": "enum",
    "adp-cvss-severity": "enum",
    "cvss-severity": "enum",
    "exploit-type": "enum",
    "kev-ransomware-use": "enum",
    "level": "enum",
    "likelihood": "enum",
    "likelihood-of-exploit": "enum",
    "maturity": "enum",
    "part": "enum",
    "rdf:type": "enum",
    "severity": "enum",
    "state": "enum",
    "status": "enum",
    # id
    "addresses-vulnerability": "id",
    "adp-affects-cpe": "id",
    "adp-related-weakness": "id",
    "affects-cpe": "id",
    "attributed-to": "id",
    "belongs-to-tactic": "id",
    "can-also-be": "id",
    "can-follow": "id",
    "can-precede": "id",
    "child-of": "id",
    "covers-tactic": "id",
    "detects": "id",
    "detects-subtechnique": "id",
    "detects-technique": "id",
    "engages-technique": "id",
    "exploits-cve": "id",
    "maps-to-d3fend": "id",
    "maps-to-technique": "id",
    "misp-related": "id",
    "mitigates": "id",
    "parent-of": "id",
    "peer-of": "id",
    "related-attack-id": "id",
    "related-attack-pattern": "id",
    "related-attack-tactic": "id",
    "related-attack-technique": "id",
    "related-cve": "id",
    "related-weakness": "id",
    "requires": "id",
    "similar-to": "id",
    "starts-with": "id",
    "subtechnique-of": "id",
    "targets": "id",
    "used-by": "id",
    "uses": "id",
    "uses-technique": "id",
    "variant-of": "id",
    "vulnerability-of": "id",
    # number
    "adp-cvss-base-score": "number",
    "attribution-confidence": "number",
    "cvss-base-score": "number",
    "epss-percentile": "number",
    "epss-score": "number",
    # string
    "affects-package": "string",
    "alias": "string",
    "analytic-type": "string",
    "assigner": "string",
    "author": "string",
    "cfr-suspected-state-sponsor": "string",
    "consequence-impact": "string",
    "consequence-scope": "string",
    "country": "string",
    "coverage-level": "string",
    "cvss-vector": "string",
    "d3fend-definition": "string",
    "d3fend-name": "string",
    "definition": "string",
    "description": "string",
    "domain": "string",
    "fixed-in": "string",
    "galaxy": "string",
    "information-domain": "string",
    "introduction-phase": "string",
    "kev-description": "string",
    "kev-name": "string",
    "kev-notes": "string",
    "kev-product": "string",
    "kev-required-action": "string",
    "kev-vendor": "string",
    "logsource-category": "string",
    "logsource-product": "string",
    "logsource-service": "string",
    "name": "string",
    "platform": "string",
    "product": "string",
    "shortname": "string",
    "subtype": "string",
    "summary": "string",
    "synonym": "string",
    "targets-country": "string",
    "targets-sector": "string",
    "title": "string",
    "vendor": "string",
    "version": "string",
    # url
    "url": "url",
}


def get_object_type(predicate: str, default: str = "string") -> str:
    """Get the object type for a predicate."""
    t = PREDICATE_TYPES.get(predicate)
    if t:
        return t
    if predicate.startswith("ssvc-"):
        return "enum"
    return default


def meta_json(d: dict | None) -> str:
    """Convert a metadata dict to a compact JSON string, or empty string if None/empty."""
    if not d:
        return ""
    return json.dumps(d, separators=(",", ":"))


def extract_cvss_meta(metric: dict) -> tuple[dict | None, str]:
    """Extract CVSS data from a metric dict, returning (cvss_dict, meta_json_str).

    Returns (None, "") if no CVSS data found.
    """
    cvss_v4 = metric.get("cvssV4_0")
    cvss_v31 = metric.get("cvssV3_1")
    cvss_v30 = metric.get("cvssV3_0")
    cvss = cvss_v4 or cvss_v31 or cvss_v30
    if not cvss:
        return None, ""
    cvss_meta: dict = {}
    if cvss.get("vectorString"):
        cvss_meta["cvss_vector"] = cvss["vectorString"]
    if cvss_v4:
        cvss_meta["cvss_version"] = "4.0"
    elif cvss_v31:
        cvss_meta["cvss_version"] = "3.1"
    elif cvss_v30:
        cvss_meta["cvss_version"] = "3.0"
    return cvss, meta_json(cvss_meta)


def merge_meta(meta_list: list[str]) -> str:
    """Merge multiple meta JSON strings into one.

    Same keys with different values become lists; unique keys are unioned.
    """
    merged: dict = {}
    for m in meta_list:
        if not m:
            continue
        try:
            d = json.loads(m)
        except (json.JSONDecodeError, TypeError):
            continue
        for k, v in d.items():
            if k not in merged:
                merged[k] = v
            elif merged[k] != v:
                existing = merged[k]
                if not isinstance(existing, list):
                    existing = [existing]
                if isinstance(v, list):
                    for item in v:
                        if item not in existing:
                            existing.append(item)
                elif v not in existing:
                    existing.append(v)
                merged[k] = existing
    return meta_json(merged)


# ---------------------------------------------------------------------------
# Parquet output
# ---------------------------------------------------------------------------

PARQUET_SCHEMA = pa.schema(
    [
        pa.field("subject", pa.string()),
        pa.field("predicate", pa.string()),
        pa.field("object", pa.string()),
        pa.field("source", pa.string()),
        pa.field("object_type", pa.string()),
        pa.field("meta", pa.string()),
    ]
)

PARQUET_FORMATS = {
    "v1": {"version": "1.0", "compression": "gzip"},
    "v2": {"version": "2.6", "compression": "snappy"},
}


COLUMNS = ["subject", "predicate", "object", "source", "object_type", "meta"]


def triples_to_dataframe(
    triples: list[tuple[str, str, str, str, str, str]],
) -> pd.DataFrame:
    """Convert list of (subject, predicate, object, source, object_type, meta) tuples."""
    return pd.DataFrame(triples, columns=COLUMNS)


def write_parquet(df: pd.DataFrame, path: Path, parquet_format: str = "v2") -> None:
    """Write a DataFrame of triples to a Parquet file."""
    pq_opts = PARQUET_FORMATS[parquet_format]
    table = pa.table(
        {col: df[col] for col in COLUMNS},
        schema=PARQUET_SCHEMA,
    )
    pq.write_table(table, path, **pq_opts)
    logger.info("Wrote %s (%d triples, format=%s)", path, len(df), parquet_format)


def write_triples_streaming(
    triples_iter,
    path: Path,
    parquet_format: str = "v2",
    batch_size: int = 100_000,
) -> int:
    """Write enriched triples to Parquet in batches.

    Each triple is a 6-tuple: (subject, predicate, object, source, object_type, meta).
    Avoids loading all triples into memory at once.  Returns the total written.
    """
    pq_opts = PARQUET_FORMATS[parquet_format]
    writer = None
    total = 0
    batch: list[tuple[str, str, str, str, str, str]] = []

    def _flush(batch):
        cols = list(zip(*batch, strict=True))
        return pa.table(
            {name: list(col) for name, col in zip(COLUMNS, cols, strict=True)},
            schema=PARQUET_SCHEMA,
        )

    try:
        for triple in triples_iter:
            batch.append(triple)
            if len(batch) >= batch_size:
                if writer is None:
                    writer = pq.ParquetWriter(path, PARQUET_SCHEMA, **pq_opts)
                writer.write_table(_flush(batch))
                total += len(batch)
                batch.clear()

        # Flush remaining
        if batch:
            if writer is None:
                writer = pq.ParquetWriter(path, PARQUET_SCHEMA, **pq_opts)
            writer.write_table(_flush(batch))
            total += len(batch)
    finally:
        if writer is not None:
            writer.close()

    logger.info("Wrote %s (%d triples, format=%s)", path, total, parquet_format)
    return total


def deduplicate_combined(
    df: pd.DataFrame,
) -> tuple[pd.DataFrame, dict]:
    """Deduplicate triples, merging source and meta for duplicate (s,p,o) rows.

    Returns (deduplicated_df, stats) where stats contains:
      - dup_rows: total rows involved in duplicates
      - dup_unique: number of unique (s,p,o) triples that had duplicates
      - by_source: dict mapping source name to count of duplicate rows
    """
    dup_mask = df.duplicated(subset=["subject", "predicate", "object"], keep=False)
    n_dup_rows = int(dup_mask.sum())

    if not n_dup_rows:
        return df, {"dup_rows": 0, "dup_unique": 0, "by_source": {}}

    dupes = df[dup_mask]
    stats = {
        "dup_rows": n_dup_rows,
        "dup_unique": int(
            dupes.drop_duplicates(subset=["subject", "predicate", "object"]).shape[0]
        ),
        "by_source": dupes.groupby("source").size().sort_values(ascending=False).to_dict(),
    }

    merged = (
        dupes.groupby(["subject", "predicate", "object"], sort=False)
        .agg(
            source=("source", lambda x: ",".join(sorted(set(x)))),
            object_type=("object_type", "first"),
            meta=("meta", lambda x: merge_meta(list(x))),
        )
        .reset_index()
    )

    return pd.concat([df[~dup_mask], merged], ignore_index=True), stats


# ---------------------------------------------------------------------------
# Source fingerprinting (skip conversion when source data is unchanged)
# ---------------------------------------------------------------------------

METADATA_FILE = PROJECT_ROOT / "hf_dataset" / ".metadata.json"


def load_metadata() -> dict:
    """Load the shared metadata file (used by both converter and workflow)."""
    if METADATA_FILE.exists():
        return json.loads(METADATA_FILE.read_text())
    return {}


def save_metadata(metadata: dict) -> None:
    """Write the shared metadata file."""
    METADATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    METADATA_FILE.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")


def load_fingerprints() -> dict[str, str]:
    """Load converter fingerprints from the metadata file."""
    return load_metadata().get("converter_fingerprints", {})


def save_fingerprint(source: str, fingerprint: str) -> None:
    """Save a single converter fingerprint to the metadata file."""
    meta = load_metadata()
    meta.setdefault("converter_fingerprints", {})[source] = fingerprint
    save_metadata(meta)


def save_fingerprints(fingerprints: dict[str, str]) -> None:
    """Save multiple converter fingerprints at once (for parallel-safe batch saving)."""
    meta = load_metadata()
    meta.setdefault("converter_fingerprints", {}).update(fingerprints)
    save_metadata(meta)


def source_changed(output_dir: Path, source: str, source_path: str) -> bool:
    """Check if a source has changed since its last successful conversion.

    Compares the source filename (which embeds the version) against the
    stored fingerprint.  Returns True if conversion is needed.
    """
    parquet_path = output_dir / f"{source}.parquet"
    if not parquet_path.exists():
        return True
    fingerprint = Path(source_path).name
    stored = load_fingerprints().get(source)
    return stored != fingerprint


# ---------------------------------------------------------------------------
# Unified remote fingerprinting (used by both CLI and CI workflow)
# ---------------------------------------------------------------------------

# Maps each source to its fingerprint method:
#   "github_sha:<owner>/<repo>/<branch>" - GitHub commit SHA
#   "github_release:<owner>/<repo>" - GitHub latest release tag
#   "http:<url>" - Last-Modified / ETag from HTTP HEAD
SOURCE_FINGERPRINT_METHODS: dict[str, str] = {
    "attack": "github_sha:mitre-attack/attack-stix-data/master",
    "capec": "http:https://capec.mitre.org/data/xml/capec_latest.xml",
    "cwe": "http:https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
    "cve": "github_release:CVEProject/cvelistV5",
    "cpe": "http:https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz",
    "d3fend": "http:https://d3fend.mitre.org/ontologies/d3fend.json",
    "atlas": "http:https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml",
    "car": "github_sha:mitre-attack/car/master",
    "engage": "http:https://raw.githubusercontent.com/mitre/engage/main/Data/json/attack_mapping.json",
    "epss": "http:https://epss.cyentia.com/epss_scores-current.csv.gz",
    "kev": "http:https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "vulnrichment": "github_sha:cisagov/vulnrichment/develop",
    "ghsa": "github_sha:github/advisory-database/main",
    "sigma": "github_release:SigmaHQ/sigma",
    "exploitdb": "http:https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
    "misp_galaxy": "github_sha:MISP/misp-galaxy/main",
}


def get_remote_fingerprint(source: str) -> str:
    """Get the current remote fingerprint for a source.

    Returns a version string suitable for comparison with stored metadata.
    Uses the method defined in SOURCE_FINGERPRINT_METHODS.
    Returns empty string on failure.
    """
    method = SOURCE_FINGERPRINT_METHODS.get(source)
    if not method:
        logger.warning("No fingerprint method configured for source '%s'", source)
        return ""

    try:
        if method.startswith("github_sha:"):
            parts = method[len("github_sha:") :].split("/", 2)
            owner, repo, branch = parts[0], parts[1], parts[2]
            sha = _github_commit_sha(owner, repo, branch)
            return f"sha:{sha}"
        if method.startswith("github_release:"):
            parts = method[len("github_release:") :].split("/", 1)
            owner, repo = parts[0], parts[1]
            tag = _github_release_tag(owner, repo)
            return f"tag:{tag}"
        if method.startswith("http:"):
            url = method[len("http:") :]
            head = requests.head(url, timeout=30, allow_redirects=True)
            lm = head.headers.get("Last-Modified", "")
            if lm:
                return f"lm:{lm}"
            etag = head.headers.get("ETag", "")
            if etag:
                return f"etag:{etag}"
    except (requests.RequestException, OSError, ValueError) as e:
        logger.warning("Failed to get remote fingerprint for '%s': %s", source, e)
    return ""


def get_all_remote_fingerprints() -> dict[str, str]:
    """Get remote fingerprints for all configured sources.

    Returns a dict mapping source name to its current fingerprint.
    Sources that fail to fetch are omitted.
    """
    fingerprints = {}
    for source in SOURCE_FINGERPRINT_METHODS:
        fp = get_remote_fingerprint(source)
        if fp:
            fingerprints[source] = fp
            logger.info("  %s: %s", source, fp)
        else:
            logger.warning("  %s: failed to get fingerprint", source)
    return fingerprints


def check_sources_changed(previous_fingerprints: dict[str, str]) -> dict[str, bool]:
    """Compare current remote fingerprints against stored ones.

    Returns a dict mapping source name to whether it has changed.
    """
    changed = {}
    for source in SOURCE_FINGERPRINT_METHODS:
        current = get_remote_fingerprint(source)
        stored = previous_fingerprints.get(source, "")
        is_changed = not current or current != stored
        changed[source] = is_changed
        status = "CHANGED" if is_changed else "unchanged"
        logger.info("  %8s: %s (current=%s, stored=%s)", source.upper(), status, current, stored)
    return changed


# ---------------------------------------------------------------------------
# Dataset README update (counts + timestamp)
# ---------------------------------------------------------------------------

DATASET_README = PROJECT_ROOT / "hf_dataset" / "README.md"

ALL_PARQUET_NAMES = [
    "enterprise",
    "mobile",
    "ics",
    "attack-all",
    "capec",
    "cwe",
    "cve",
    "cpe",
    "d3fend",
    "atlas",
    "car",
    "engage",
    "epss",
    "kev",
    "vulnrichment",
    "ghsa",
    "sigma",
    "exploitdb",
    "misp_galaxy",
    "combined",
]


_PARQUET_TO_SOURCE = {
    "enterprise": "attack",
    "mobile": "attack",
    "ics": "attack",
    "attack-all": "attack",
}


def update_dataset_readme(
    output_dir: Path,
    failed_sources: list[str] | None = None,
) -> None:
    """Update hf_dataset/README.md with real triple counts, status, and timestamp."""
    from datetime import UTC, datetime  # noqa: PLC0415 — avoid import at module level

    if not DATASET_README.exists():
        logger.warning("Dataset README not found at %s", DATASET_README)
        return

    text = DATASET_README.read_text()

    counts = {}
    for name in ALL_PARQUET_NAMES:
        path = output_dir / f"{name}.parquet"
        if path.exists():
            counts[name] = pq.read_metadata(path).num_rows

    if not counts:
        logger.warning("No parquet files found in %s, skipping README update", output_dir)
        return

    # Build status mapping
    failed = set(failed_sources or [])
    statuses: dict[str, str] = {}
    for name in ALL_PARQUET_NAMES:
        parent_source = _PARQUET_TO_SOURCE.get(name, name)
        statuses[name] = "Last good version" if parent_source in failed else "Current"

    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Ensure the table has a Status column header
    if "| Status |" not in text:
        text = text.replace(
            "| Config | Description | Est. Triples |",
            "| Config | Description | Est. Triples | Status |",
        )
        text = text.replace(
            "|--------|-------------|-------------|",
            "|--------|-------------|-------------|--------|",
        )

    for name, count in counts.items():
        status = statuses.get(name, "Current")
        # Match config name + description columns, then replace everything
        # through end of row (handles any number of trailing columns from
        # previous runs that may have appended extra | Current | entries).
        pattern = rf"(\| `{re.escape(name)}`[^|]*\|[^|]*\|).*\|"
        replacement = rf"\1 {count:,} | {status} |"
        text = re.sub(pattern, replacement, text)

    text = re.sub(
        r"\*Last updated:.*?\*",
        f"*Last updated: {now}*",
        text,
    )

    # Update fallback note
    fallback_marker = "<!-- fallback-status-note -->"
    # Remove existing note block (marker + any following blockquote lines)
    text = re.sub(
        rf"{re.escape(fallback_marker)}\n(?:>.*\n)*",
        "",
        text,
    )
    fallback_names = [n for n, s in statuses.items() if s == "Last good version"]
    if fallback_names:
        sources_list = ", ".join(f"`{n}`" for n in fallback_names)
        singular = len(fallback_names) == 1
        verb = "uses its" if singular else "use their"
        note = (
            f"{fallback_marker}\n"
            f"> **Note:** {sources_list} failed conversion and {verb} "
            f"last known good version. The `combined` config includes "
            f"{'this fallback' if singular else 'these fallback'} version"
            f"{'.' if singular else 's.'}\n\n"
        )
        text = text.replace(
            "\n## Knowledge Graph Structure",
            f"\n{note}## Knowledge Graph Structure",
        )

    DATASET_README.write_text(text)
    logger.info(
        "Updated %s with counts: %s",
        DATASET_README,
        {k: f"{v:,}" for k, v in counts.items()},
    )
