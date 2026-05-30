# CLAUDE.md

Guidance for Claude Code when working in this repository. Optimized for agents — be concise, verify before editing, prefer tools over guesses.

## Project Overview

`security-kg` converts **24 security data sources** into **Subject-Predicate-Object (SPO) knowledge-graph triples** stored as Parquet. Every row is a 6-tuple: `(subject, predicate, object, source, object_type, meta)` — all string columns.

- Per-source outputs land in `output/<source>.parquet`.
- `output/combined.parquet` merges everything with case-insensitive dedup on `(subject, predicate, object)`.
- The HuggingFace dataset `s0u9ata/security-kg` is the published artifact (refreshed weekly via CI).

## Common Commands

```bash
# Install
pip install -r requirements.txt
pip install -e ".[dev]"   # adds pytest, ruff, pre-commit, datasets

# Unit tests (no network)
python -m pytest tests/ --ignore=tests/test_integration.py

# Single test file / single test
python -m pytest tests/test_convert_kev.py -v
python -m pytest tests/test_convert_kev.py::TestKevTriples::test_basic_properties -v

# Integration tests (require network)
python -m pytest tests/test_integration.py -m integration

# Lint & format
ruff check .
ruff format --check .
ruff check --fix .

# Convert all 24 sources -> output/*.parquet
python src/convert.py

# Fast local test on specific sources
python src/convert.py --sources kev epss --limit 100

# Parallel conversion
python src/convert.py --parallel --workers 8
```

PowerShell users: chain with `;` instead of `&&`.

## Architecture

```
src/convert.py              # CLI orchestrator; ProcessPoolExecutor for --parallel
src/convert_<source>.py     # one module per source (24 of them)
src/convert_attack.py       # special: handles 3 domains -> attack-all.parquet
src/common.py               # Triple type, PREDICATE_TYPES, PARQUET_SCHEMA,
                            # downloaders, Parquet I/O, dedup, fingerprints
output/                     # per-source Parquet + combined.parquet
source/                     # cached downloads (gitignored)
hf_dataset/                 # dataset card + .metadata.json (source fingerprints)
.github/workflows/          # ci.yml (lint+test), update-dataset.yml (weekly)
```

**ATT&CK** has three domains (`enterprise`, `mobile`, `ics`) → separate Parquets plus a merged `attack-all.parquet`.

The weekly pipeline (`update-dataset.yml`, Mondays 06:00 UTC) compares remote fingerprints, converts only changed sources, downloads unchanged Parquets from HuggingFace, rebuilds `combined.parquet`, validates row counts, regenerates dashboard stats, and uploads to the Hub.

## Adding a New Converter

Every converter module follows this interface:

```python
# src/convert_mysource.py
from common import Triple, download_file, make_triple_fn

SOURCE = "mysource"
_t = make_triple_fn(SOURCE)

def download_mysource(cache_dir: str | None = None, *, force_download: bool = False) -> str:
    """Download source data, return local file path as str."""
    ...

def extract_mysource_triples(path: str) -> list[Triple]:
    """Parse downloaded data, return triples."""
    ...
```

**Registration checklist when adding a source:**

1. Append the source key to `ALL_SOURCES` in `src/convert.py`.
2. Add an entry to `SOURCE_CONVERTERS` in `src/convert.py`: `(module_name, download_fn, extract_fn)`.
3. Register any new predicates in `PREDICATE_TYPES` in `src/common.py` (exception: `ssvc-*` predicates auto-map to type `"enum"`).
4. Update `README.md` — sources line, output file table, cross-source mermaid diagram.
5. Update `hf_dataset/README.md` — YAML `tags`, `configs` block, Configurations table, Source Data table, Predicate Reference section.
6. Add `tests/test_convert_<name>.py` following the pattern below.
7. Add fingerprint logic to `SOURCE_FINGERPRINT_METHODS` in `common.py` (used by CI change detection) and add the workflow plumbing in `update-dataset.yml`.

## Key Conventions

### Triple building

```python
_t = make_triple_fn("mysource")
triple = _t(subject, predicate, object)                          # meta defaults to ""
triple = _t(subject, predicate, object, meta_json({"k": "v"}))   # with metadata
```

`object_type` is inferred from `PREDICATE_TYPES`. **All predicates must be registered there** or in the `ssvc-*` exception.

### CVSS & long text

- Use `extract_cvss_meta(metric_dict)` from `common.py` — handles v4.0/3.1/3.0 priority, returns `(cvss_dict, meta_json_str)`.
- Use `truncate_text(text, max_len=2000)` for description-like fields.

### Downloading & caching

- Use `download_file`, `download_zip`, `download_tar_gz`, `download_gzip` from `common.py`.
- For GitHub repos use `download_github_zip` — uses the Commits API for a stable fingerprint (HTTP `Last-Modified`/`ETag` are unreliable for `codeload.github.com`).
- Cached files live in `source/` and are re-downloaded only when the upstream fingerprint changes.
- `GITHUB_TOKEN` env var is picked up automatically for authenticated GitHub API calls.

### Parquet output

- Schema is fixed: `subject`, `predicate`, `object`, `source`, `object_type`, `meta` — all `string`. **Do not change.**
- Large sources: `write_triples_streaming()` (batched, memory-safe).
- Small sources: `write_parquet()`.
- Default format `v2` (Parquet 2.6 + snappy); `v1` (1.0 + gzip) available for backward compat via `--parquet-format v1`.

### Deduplication & cross-source linking

`deduplicate_combined` matches case-insensitively on `(subject, predicate, object)`.

- **CVE IDs must be uppercase** (`CVE-2024-1234`, not `cve-2024-1234`) — otherwise dedup misses cross-source links.
- Winning row's `source` becomes a sorted, comma-joined union (e.g., `"kev,nvd,osv"`).
- `meta` columns are merged via `merge_meta()` — conflicting values for the same key become lists.

### Meta field

Compact JSON string built via `meta_json(dict)`. Use `merge_meta(meta_list)` only when combining metadata for a deduplicated triple.

### Source fingerprinting

```python
if source_changed(out_dir, source, path):
    # ... do the conversion ...
    save_fingerprint(source, Path(path).name)   # updates hf_dataset/.metadata.json
```

### Logging

- File logs go to `logs/<source>.log` when `--log-dir` is set (CI default).
- On Windows, `FileHandler` opens with `encoding="utf-8"`, but **log format strings must stay ASCII-only** (use `->` not `→`) to avoid `cp1252` console encoding errors.

## Testing Pattern

Tests live in `tests/test_convert_<source>.py`:

1. Define a minimal sample dataset as a Python dict / string literal.
2. Use the `tmp_path` pytest fixture to write it to a temp file.
3. Call `extract_<source>_triples(path)` directly — **no network, no downloads**.
4. Assert with set membership on the SPO portion: `{t[:3] for t in triples}`.

Integration tests in `tests/test_integration.py` are network-dependent and excluded from CI unit runs (`--ignore=tests/test_integration.py`).

## Style & Tooling

- **Line length: 100** (enforced by ruff).
- **Python 3.13** pinned in CI (`.github/workflows/ci.yml`).
- `requires-python = ">=3.12"` in `pyproject.toml`.
- `ruff target-version = "py312"` in `pyproject.toml`.
- **When bumping any of the three Python versions above, bump all three together** — otherwise ruff won't flag syntax issues accurately.
- Ruff lint set: `E, W, F, I, UP, B, SIM`.

## Do / Don't

✅ **Do**
- Uppercase CVE IDs everywhere (`CVE-YYYY-NNNN`).
- Register every new predicate in `PREDICATE_TYPES`.
- Use `make_triple_fn(SOURCE)` instead of constructing tuples by hand.
- Run `ruff format` and `ruff check` before committing.
- Update **both** `README.md` and `hf_dataset/README.md` when adding/removing a source.
- Use `write_triples_streaming` for any source likely to exceed ~500K triples.

❌ **Don't**
- Add non-ASCII characters to log format strings.
- Change the Parquet schema columns or their types.
- Bypass the fingerprint cache by hand-editing `hf_dataset/.metadata.json`.
- Commit anything under `output/` or `source/` (both gitignored).
- Call `semantic_search`-style fuzzy lookups when an exact symbol grep is faster.
- Parallelize work that mutates `hf_dataset/.metadata.json` without coordination.

---

For more detail, see `README.md`. This file is mirrored to `AGENTS.md` and `.github/copilot-instructions.md` — keep all three in sync when editing.

