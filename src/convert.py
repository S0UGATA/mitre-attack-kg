"""CLI orchestrator: Security Data → KG Triples (Parquet)."""

import argparse
import itertools
import json
import logging
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd
from tqdm import tqdm

from common import (
    PARQUET_FORMATS,
    PROJECT_ROOT,
    SOURCE_DIR,
    deduplicate_combined,
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
    "f3",
    "epss",
    "kev",
    "vulnrichment",
    "ghsa",
    "sigma",
    "exploitdb",
    "misp_galaxy",
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
    "f3": ("convert_f3", "download_f3", "extract_f3_triples"),
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
    "misp_galaxy": ("convert_misp_galaxy", "download_misp_galaxy", "extract_misp_galaxy_triples"),
}

LOG_FORMAT = "%(asctime)s [%(source)s] %(levelname)s: %(message)s"
LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"

LEVEL_COLORS = {
    logging.DEBUG: "\033[36m",  # cyan
    logging.INFO: "\033[32m",  # green
    logging.WARNING: "\033[33m",  # yellow
    logging.ERROR: "\033[31m",  # red
    logging.CRITICAL: "\033[1;31m",  # bold red
}
RESET = "\033[0m"
DIM = "\033[2m"
CYAN = "\033[36m"


class ColorFormatter(logging.Formatter):
    def format(self, record):
        color = LEVEL_COLORS.get(record.levelno, RESET)
        ts = self.formatTime(record, self.datefmt)
        source = getattr(record, "source", "main")
        msg = record.getMessage()
        return f"{DIM}{ts}{RESET} {CYAN}[{source}]{RESET} {color}{record.levelname}{RESET}: {msg}"


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
    console.setFormatter(ColorFormatter(datefmt=LOG_DATEFMT))
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
    limit: int | None = None,
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
    if limit is not None:
        triples = itertools.islice(triples, limit)
        logger.info("Limiting %s to %d triples", source, limit)
    out_path = out_dir / f"{source}.parquet"
    write_triples_streaming(triples, out_path, parquet_format)
    elapsed = time.monotonic() - t0
    logger.info("Finished %s in %.1fs", source, elapsed)
    return source, Path(path).name


def _convert_attack(
    domains: list[str],
    output_dir: str,
    cache_dir: str,
    parquet_format: str,
    log_dir: str | None = None,
    force: bool = False,
    limit: int | None = None,
) -> tuple[str, dict[str, str]]:
    """Convert all ATT&CK domains. Runs in a worker process.

    Returns ("attack", {domain: fingerprint, ...}) with only changed domains.
    """
    _setup_logging(Path(log_dir) if log_dir else None, "attack")
    t0 = time.monotonic()
    logger.info("Starting ATT&CK conversion for domains: %s", ", ".join(domains))

    out_dir = Path(output_dir)
    attack_dfs = []
    attack_fingerprints: dict[str, str] = {}
    attack_any_changed = False

    for domain in domains:
        stix_path = download_stix(domain, cache_dir)
        if not force and not source_changed(out_dir, domain, stix_path):
            logger.info(
                "Source %s unchanged, skipping conversion (use --force to override)", domain
            )
            existing = out_dir / f"{domain}.parquet"
            if existing.exists():
                attack_dfs.append(pd.read_parquet(existing))
            continue
        attack_any_changed = True
        df = convert_domain(domain, out_dir, cache_dir, parquet_format, stix_path=stix_path)
        if limit is not None:
            df = df.head(limit)
            logger.info("Limiting %s to %d triples", domain, limit)
        attack_fingerprints[domain] = Path(stix_path).name
        attack_dfs.append(df)

    if len(attack_dfs) > 1 and attack_any_changed:
        attack_combined = pd.concat(attack_dfs, ignore_index=True)
        attack_combined, _ = deduplicate_combined(attack_combined)
        write_parquet(attack_combined, out_dir / "attack-all.parquet", parquet_format)

    elapsed = time.monotonic() - t0
    logger.info("Finished ATT&CK in %.1fs", elapsed)
    return "attack", attack_fingerprints


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
    parser.add_argument(
        "--no-stats",
        action="store_true",
        help="Skip generating dashboard stats JSON files in hf_dataset/.stats/",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limit each source to N triples (for quick local testing)",
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

    if args.limit is not None:
        logger.info("Limiting each source to %d triples (test mode)", args.limit)

    cache_dir = args.cache_dir
    log_dir_str = str(args.log_dir)
    failed_sources: list[str] = []

    # Order sources so heaviest ones start first (maximizes parallel overlap)
    HEAVY_SOURCES_ORDER = ["cve", "ghsa", "vulnrichment", "cpe", "attack"]
    non_attack = [s for s in args.sources if s != "attack" and s in SOURCE_CONVERTERS]
    has_attack = "attack" in args.sources
    all_sources = non_attack.copy()

    # Sort: heavy sources first, then the rest in original order
    def _source_priority(s: str) -> int:
        try:
            return HEAVY_SOURCES_ORDER.index(s)
        except ValueError:
            return len(HEAVY_SOURCES_ORDER)

    all_sources.sort(key=_source_priority)

    if args.parallel and (len(all_sources) + (1 if has_attack else 0)) > 1:
        total = len(all_sources) + (1 if has_attack else 0)
        logger.info("Running %d sources in parallel with %d workers", total, args.workers)
        with ProcessPoolExecutor(max_workers=args.workers) as pool:
            futures: dict = {}

            # Submit ATT&CK as a single worker task
            if has_attack:
                futures[
                    pool.submit(
                        _convert_attack,
                        list(args.domains),
                        str(args.output_dir),
                        cache_dir,
                        args.parquet_format,
                        log_dir_str,
                        args.force,
                        args.limit,
                    )
                ] = "attack"

            # Submit non-ATT&CK sources (heavy first)
            for source in all_sources:
                futures[
                    pool.submit(
                        _convert_source,
                        source,
                        str(args.output_dir),
                        cache_dir,
                        args.parquet_format,
                        log_dir_str,
                        args.force,
                        args.limit,
                    )
                ] = source

            with tqdm(total=total, desc="Converting sources", unit="source", leave=True) as pbar:
                for future in as_completed(futures):
                    source = futures[future]
                    try:
                        if source == "attack":
                            _, attack_fps = future.result()
                            if attack_fps:
                                save_fingerprints(attack_fps)
                        else:
                            _, fp = future.result()
                            if fp:
                                save_fingerprint(source, fp)
                    except Exception:
                        logger.exception("Failed: %s", source)
                        failed_sources.append(source)
                    pbar.set_postfix_str(source)
                    pbar.update(1)
    else:
        # Sequential mode
        seq_sources = (["attack"] if has_attack else []) + all_sources
        with tqdm(
            total=len(seq_sources), desc="Converting sources", unit="source", leave=True
        ) as pbar:
            if has_attack:
                pbar.set_postfix_str("attack")
                try:
                    _, attack_fps = _convert_attack(
                        list(args.domains),
                        str(args.output_dir),
                        cache_dir,
                        args.parquet_format,
                        log_dir_str,
                        args.force,
                        args.limit,
                    )
                    if attack_fps:
                        save_fingerprints(attack_fps)
                except Exception:
                    logger.exception("Failed: attack")
                    failed_sources.append("attack")
                pbar.update(1)

            for source in all_sources:
                pbar.set_postfix_str(source)
                try:
                    _, fp = _convert_source(
                        source,
                        str(args.output_dir),
                        cache_dir,
                        args.parquet_format,
                        log_dir_str,
                        args.force,
                        args.limit,
                    )
                    if fp:
                        save_fingerprint(source, fp)
                except Exception:
                    logger.exception("Failed: %s", source)
                    failed_sources.append(source)
                pbar.update(1)

    # --- Combined (all sources) ---
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
            dfs = [pd.read_parquet(pf) for pf in parquet_files]
            combined_df = pd.concat(dfs, ignore_index=True)
            total_before = len(combined_df)

            combined_df, dup_stats = deduplicate_combined(combined_df)

            if dup_stats["dup_rows"]:
                logger.info(
                    "Found %d duplicate rows (%d unique triples) across sources:",
                    dup_stats["dup_rows"],
                    dup_stats["dup_unique"],
                )
                for src, count in dup_stats["by_source"].items():
                    logger.info("  %-20s %d rows", src, count)

            logger.info(
                "Combined: %d triples from %d sources → %d after deduplication (-%d)",
                total_before,
                len(parquet_files),
                len(combined_df),
                total_before - len(combined_df),
            )
            write_parquet(combined_df, combined_path, args.parquet_format)

    # Write conversion report for CI workflow consumption
    report = {"failed_sources": failed_sources, "timestamp": now}
    report_path = PROJECT_ROOT / "hf_dataset" / ".conversion_report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    if failed_sources:
        logger.warning("Failed sources: %s", ", ".join(failed_sources))

    if args.update_readme:
        update_dataset_readme(args.output_dir, failed_sources=failed_sources)

    if not args.no_stats:
        from generate_stats import generate_all_stats

        logger.info("Generating dashboard stats ...")
        generate_all_stats(args.output_dir)

    elapsed_total = time.monotonic() - t0_total
    logger.info("All done in %.1fs", elapsed_total)


if __name__ == "__main__":
    main()
