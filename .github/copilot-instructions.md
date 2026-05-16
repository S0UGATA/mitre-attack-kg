# Copilot Instructions

## Commands

```bash
# Install dependencies
pip install -r requirements.txt
pip install -e ".[dev]"   # includes pytest, ruff, pre-commit

# Run all unit tests
python -m pytest tests/ --ignore=tests/test_integration.py

# Run a single test file
python -m pytest tests/test_convert_kev.py -v

# Run a single test
python -m pytest tests/test_convert_kev.py::TestKevTriples::test_basic_properties -v

# Integration tests (require network access)
python -m pytest tests/test_integration.py -m integration

# Lint
ruff check .
ruff format --check .
ruff check --fix .  # auto-fix

# Convert all 24 sources → output/*.parquet
python src/convert.py

# Convert specific sources (fast local test)
python src/convert.py --sources kev epss --limit 100

# Parallel conversion
python src/convert.py --parallel --workers 8
```

## Architecture

The project converts 24 security data sources into **Subject-Predicate-Object (SPO) triples** stored as Parquet files. Each triple is a 6-tuple: `(subject, predicate, object, source, object_type, meta)`.

**Data flow:**
1. `src/convert.py` — CLI orchestrator; dispatches to per-source converters, optionally in parallel via `ProcessPoolExecutor`
2. `src/convert_<source>.py` — one module per data source (e.g., `convert_kev.py`, `convert_cve.py`)
3. `src/common.py` — shared utilities: downloading, caching, Parquet I/O, the `Triple` type, `PREDICATE_TYPES`, and `PARQUET_SCHEMA`
4. `output/<source>.parquet` — per-source output; `output/combined.parquet` merges all sources with deduplication

ATT&CK is special: it has three domains (`enterprise`, `mobile`, `ics`) handled by `convert_attack.py` and merged into `attack-all.parquet`.

The `hf_dataset/` directory contains the HuggingFace dataset card and `.metadata.json` (source fingerprints used for change detection).

The production pipeline runs via `.github/workflows/update-dataset.yml` — triggered weekly (Monday 06:00 UTC) or manually. It supports `--parallel`, `--workers`, `--force`, `--sources`, and `--limit` flags. The CI lint/test workflow (`.github/workflows/ci.yml`) runs on every push/PR to `main`.

## Key Conventions

### Adding a new converter

Every converter module follows the same interface:
```python
SOURCE = "mysource"

def download_mysource(cache_dir: str | None = None, *, force_download: bool = False) -> str:
    """Downloads source data, returns local file path string."""
    ...

_t = make_triple_fn(SOURCE)  # from common.py

def extract_mysource_triples(path: str) -> list[Triple]:
    """Parses downloaded data and returns triples."""
    ...
```

Register the new source in `convert.py`: add to `ALL_SOURCES` tuple and `SOURCE_CONVERTERS` dict as `(module_name, download_fn, extract_fn)`.

**When adding a new source, also update both READMEs:**
- `README.md` — add to the sources line, the output file table, and the cross-source links diagram
- `hf_dataset/README.md` — add a tag in the YAML front matter, a `config_name` entry, a row in the Configurations table, a row in the Source Data table, and a Predicate Reference section

### Triple building

Use `make_triple_fn(source)` from `common.py` to create a bound triple builder:
```python
_t = make_triple_fn("mysource")
triple = _t(subject, predicate, object)            # meta defaults to ""
triple = _t(subject, predicate, object, meta_json({"key": "val"}))
```

`object_type` is inferred automatically from `PREDICATE_TYPES` in `common.py`. **All predicates must be registered in `PREDICATE_TYPES`** — add new ones there to keep the schema consistent. Exception: any predicate starting with `ssvc-` automatically gets type `"enum"` without needing an explicit entry.

For CVSS data, use the shared helper `extract_cvss_meta(metric_dict)` from `common.py` — it handles v4.0/3.1/3.0 priority and returns `(cvss_dict, meta_json_str)`. Use `truncate_text(text, max_len=2000)` to safely cap long text fields.

### Downloading and caching

- Use `download_file()`, `download_zip()`, `download_tar_gz()`, `download_gzip()` from `common.py`
- For GitHub repos, use `download_github_zip()` — it uses the Commits API for a stable fingerprint instead of unreliable HTTP headers
- Files are versioned by `Last-Modified`/`ETag` and cached in `source/` (default); only re-downloaded when the source changes
- `GITHUB_TOKEN` env var is used automatically for authenticated GitHub API requests

### Parquet output

- Schema is fixed: `subject`, `predicate`, `object`, `source`, `object_type`, `meta` — all strings
- Use `write_triples_streaming()` for large sources (batched, avoids memory issues); use `write_parquet()` for small sources
- Default format is `v2` (Parquet 2.6 + snappy); `v1` (1.0 + gzip) for backward compat

### Testing pattern

Tests live in `tests/test_convert_<source>.py`. Each test:
1. Defines a minimal sample dataset as a Python dict/string literal
2. Uses a `tmp_path` pytest fixture to write it to a temp file
3. Calls `extract_<source>_triples(path)` directly — no network, no downloads
4. Asserts on triple content using set membership: `{t[:3] for t in triples}`

Integration tests (`test_integration.py`) download real data and are excluded from CI unit runs.

### Meta field

The `meta` column carries optional structured data as a compact JSON string (use `meta_json(dict)` from `common.py`). Use `merge_meta()` when combining metadata from multiple sources for deduplicated triples.

### Deduplication and cross-source linking

`deduplicate_combined` merges on **uppercase** `(subject, predicate, object)` — the match is case-insensitive. This means:
- CVE IDs **must be uppercase** (`CVE-2024-1234`, not `cve-2024-1234`) so they deduplicate correctly across sources
- The winning row's `source` column becomes a comma-joined sorted union (e.g., `"kev,nvd,osv"`)
- The `meta` columns are merged via `merge_meta()` — same keys with different values become lists

### Logging

Log files are written to `logs/<source>.log` when `--log-dir` is set (the default in the CI workflow). On Windows, `FileHandler` is opened with `encoding='utf-8'`; avoid non-ASCII characters in log message format strings (use `->` not `→`) to prevent `cp1252` encoding errors on the console.

### Source fingerprinting

Converters skip re-conversion if the source file is unchanged. `source_changed(out_dir, source, path)` compares the cached filename fingerprint. After conversion, call `save_fingerprint(source, Path(path).name)` to update `hf_dataset/.metadata.json`.

### Line length and Python version

100 characters (enforced by ruff). CI pins **Python 3.13**; `requires-python = ">=3.12"` in `pyproject.toml`.

### Python version and ruff alignment

The ruff `target-version` is currently `py312`. When bumping either `requires-python` in `pyproject.toml` **or** the Python version in `.github/workflows/ci.yml`, also update `ruff target-version` to match — otherwise ruff won't flag syntax issues accurately.
