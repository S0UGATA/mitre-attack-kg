"""CLI orchestrator: Security Data → KG Triples (Parquet)."""

import argparse
import logging
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from common import (
    PARQUET_FORMATS,
    PARQUET_SCHEMA,
    PROJECT_ROOT,
    SOURCE_DIR,
    save_fingerprint,
    save_fingerprints,
    source_changed,
    update_dataset_readme,
    write_parquet,
    write_triples_streaming,
)
from convert_attack import DOMAINS, convert_domain, download_stix

logger = logging.getLogger(__name__)

ALL_SOURCES = (
    "attack",
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
)

SOURCE_CONVERTERS = {
    "capec": ("convert_capec", "download_capec", "extract_capec_triples"),
    "cwe": ("convert_cwe", "download_cwe", "extract_cwe_triples"),
    "cve": ("convert_cve", "download_cve", "extract_cve_triples"),
    "cpe": ("convert_cpe", "download_cpe", "extract_cpe_triples"),
    "d3fend": ("convert_d3fend", "download_d3fend", "extract_d3fend_triples"),
    "atlas": ("convert_atlas", "download_atlas", "extract_atlas_triples"),
    "car": ("convert_car", "download_car", "extract_car_triples"),
    "engage": ("convert_engage", "download_engage", "extract_engage_triples"),
    "epss": ("convert_epss", "download_epss", "extract_epss_triples"),
    "kev": ("convert_kev", "download_kev", "extract_kev_triples"),
    "vulnrichment": (
        "convert_vulnrichment",
        "download_vulnrichment",
        "extract_vulnrichment_triples",
    ),
    "ghsa": ("convert_ghsa", "download_ghsa", "extract_ghsa_triples"),
    "sigma": ("convert_sigma", "download_sigma", "extract_sigma_triples"),
    "exploitdb": ("convert_exploitdb", "download_exploitdb", "extract_exploitdb_triples"),
}

LOG_FORMAT = "%(asctime)s [%(source)s] %(levelname)s: %(message)s"
LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"


class SourceFilter(logging.Filter):
    """Inject a source tag into every log record."""

    def __init__(self, source: str):
        super().__init__()
        self.source = source

    def filter(self, record):
        record.source = self.source
        return True


def _setup_logging(log_dir: Path | None, source: str = "main") -> None:
    """Configure logging with console + optional file output, tagged by source."""
    root = logging.getLogger()
    root.setLevel(logging.INFO)

    # Remove existing handlers (important for worker processes)
    root.handlers.clear()

    filt = SourceFilter(source)

    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=LOG_DATEFMT))
    console.addFilter(filt)
    root.addHandler(console)

    if log_dir:
        log_dir.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_dir / f"{source}.log", mode="w")
        fh.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=LOG_DATEFMT))
        fh.addFilter(filt)
        root.addHandler(fh)


def _convert_source(
    source: str,
    output_dir: str,
    cache_dir: str,
    parquet_format: str,
    log_dir: str | None = None,
    force: bool = False,
) -> tuple[str, str | None]:
    """Convert a single non-ATT&CK source. Runs in a worker process.

    Returns (source_name, fingerprint) or (source_name, None) if skipped.
    Fingerprint saving is deferred to the main process (parallel safety).
    """
    _setup_logging(Path(log_dir) if log_dir else None, source)
    t0 = time.monotonic()
    logger.info("Starting %s conversion", source)
    mod_name, dl_name, ext_name = SOURCE_CONVERTERS[source]
    mod = __import__(mod_name)
    path = getattr(mod, dl_name)(cache_dir)

    out_dir = Path(output_dir)
    if not force and not source_changed(out_dir, source, path):
        logger.info("Source %s unchanged, skipping conversion (use --force to override)", source)
        return source, None

    triples = getattr(mod, ext_name)(path)
    out_path = out_dir / f"{source}.parquet"
    write_triples_streaming(triples, out_path, parquet_format)
    elapsed = time.monotonic() - t0
    logger.info("Finished %s in %.1fs", source, elapsed)
    return source, Path(path).name


def main():
    parser = argparse.ArgumentParser(description="Security Data → KG Triples (Parquet)")
    parser.add_argument(
        "--domains",
        nargs="+",
        default=list(DOMAINS.keys()),
        choices=list(DOMAINS.keys()),
        help="ATT&CK domains to convert (default: all)",
    )
    parser.add_argument(
        "--sources",
        nargs="+",
        default=list(ALL_SOURCES),
        choices=list(ALL_SOURCES),
        help="Data sources to convert (default: all)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=PROJECT_ROOT / "output",
        help="Output directory for Parquet files",
    )
    parser.add_argument(
        "--cache-dir",
        type=str,
        default=str(SOURCE_DIR),
        help="Directory to cache downloaded source files (default: source/)",
    )
    parser.add_argument(
        "--parquet-format",
        choices=list(PARQUET_FORMATS.keys()),
        default="v2",
        help="Parquet format: v2 (2.6/snappy, default) or v1 (1.0/gzip, backward compat)",
    )
    parser.add_argument(
        "--no-combined",
        action="store_true",
        help="Skip generating combined.parquet (all sources merged)",
    )
    parser.add_argument(
        "--parallel",
        action="store_true",
        help="Run source conversions in parallel (uses multiple processes)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Number of parallel workers (default: 4, used with --parallel)",
    )
    parser.add_argument(
        "--log-dir",
        type=Path,
        default=PROJECT_ROOT / "logs",
        help="Directory for log files (default: logs/)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force re-conversion even if source data hasn't changed",
    )
    parser.add_argument(
        "--update-readme",
        action="store_true",
        help="Update hf_dataset/README.md with real triple counts and timestamp",
    )
    args = parser.parse_args()

    _setup_logging(args.log_dir, "main")

    t0_total = time.monotonic()
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    logger.info("Starting security-kg conversion at %s", now)
    logger.info("Sources: %s", ", ".join(args.sources))

    args.output_dir.mkdir(parents=True, exist_ok=True)

    if args.parquet_format == "v1":
        logger.info(
            "Using Parquet v1 (backward compat). "
            "For smaller files, re-run without --parquet-format or use: --parquet-format v2"
        )

    cache_dir = args.cache_dir
    log_dir_str = str(args.log_dir)

    # --- ATT&CK domains ---
    if "attack" in args.sources:
        logger.info("Converting ATT&CK domains: %s", ", ".join(args.domains))
        attack_dfs = []
        attack_any_changed = False
        attack_fingerprints: dict[str, str] = {}
        for domain in args.domains:
            stix_path = download_stix(domain, cache_dir)
            if not args.force and not source_changed(args.output_dir, domain, stix_path):
                logger.info(
                    "Source %s unchanged, skipping conversion (use --force to override)", domain
                )
                # Load existing parquet for the combined file
                existing = args.output_dir / f"{domain}.parquet"
                if existing.exists():
                    attack_dfs.append(pd.read_parquet(existing))
                continue
            attack_any_changed = True
            df = convert_domain(
                domain, args.output_dir, cache_dir, args.parquet_format, stix_path=stix_path
            )
            attack_fingerprints[domain] = Path(stix_path).name
            attack_dfs.append(df)

        if attack_fingerprints:
            save_fingerprints(attack_fingerprints)

        if len(attack_dfs) > 1 and attack_any_changed:
            attack_combined = pd.concat(attack_dfs, ignore_index=True).drop_duplicates()
            write_parquet(
                attack_combined, args.output_dir / "attack-all.parquet", args.parquet_format
            )

    # --- Non-ATT&CK sources ---
    non_attack = [s for s in args.sources if s != "attack" and s in SOURCE_CONVERTERS]

    if args.parallel and len(non_attack) > 1:
        logger.info("Running %d sources in parallel with %d workers", len(non_attack), args.workers)
        with ProcessPoolExecutor(max_workers=args.workers) as pool:
            futures = {
                pool.submit(
                    _convert_source,
                    source,
                    str(args.output_dir),
                    cache_dir,
                    args.parquet_format,
                    log_dir_str,
                    args.force,
                ): source
                for source in non_attack
            }
            for future in as_completed(futures):
                source = futures[future]
                try:
                    _, fp = future.result()
                    if fp:
                        save_fingerprint(source, fp)
                    logger.info("Completed: %s", source)
                except Exception:
                    logger.exception("Failed: %s", source)
    else:
        for source in non_attack:
            _, fp = _convert_source(
                source,
                str(args.output_dir),
                cache_dir,
                args.parquet_format,
                log_dir_str,
                args.force,
            )
            if fp:
                save_fingerprint(source, fp)

    # --- Combined (all sources) — stream from parquet files to avoid loading all into memory ---
    if not args.no_combined:
        parquet_names = []
        if "attack" in args.sources:
            parquet_names.append("attack-all")
        parquet_names.extend(non_attack)

        parquet_files = []
        for name in parquet_names:
            pf = args.output_dir / f"{name}.parquet"
            if pf.exists():
                parquet_files.append(pf)

        if len(parquet_files) > 1:
            combined_path = args.output_dir / "combined.parquet"
            pq_opts = PARQUET_FORMATS[args.parquet_format]
            writer = None
            total_rows = 0
            try:
                for pf in parquet_files:
                    for batch in pq.ParquetFile(pf).iter_batches(batch_size=500_000):
                        if writer is None:
                            writer = pq.ParquetWriter(combined_path, PARQUET_SCHEMA, **pq_opts)
                        writer.write_table(pa.Table.from_batches([batch], schema=PARQUET_SCHEMA))
                        total_rows += batch.num_rows
            finally:
                if writer is not None:
                    writer.close()
            logger.info(
                "Wrote %s (%d triples, format=%s)", combined_path, total_rows, args.parquet_format
            )

    if args.update_readme:
        update_dataset_readme(args.output_dir)

    elapsed_total = time.monotonic() - t0_total
    logger.info("All done in %.1fs", elapsed_total)


if __name__ == "__main__":
    main()
