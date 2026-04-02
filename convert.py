"""CLI orchestrator: MITRE ATT&CK / CAPEC / CWE → KG Triples (Parquet)."""

import argparse
import logging
import tempfile
from pathlib import Path

import pandas as pd

from common import PARQUET_FORMATS, triples_to_dataframe, write_parquet
from convert_attack import DOMAINS, convert_domain

logger = logging.getLogger(__name__)

ALL_SOURCES = ("attack", "capec", "cwe")


def main():
    parser = argparse.ArgumentParser(
        description="MITRE ATT&CK / CAPEC / CWE → KG Triples (Parquet)"
    )
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
        help="Data sources to convert (default: all). Use --sources attack to skip CAPEC/CWE",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).parent / "output",
        help="Output directory for Parquet files",
    )
    parser.add_argument(
        "--cache-dir",
        type=str,
        default=None,
        help="Directory to cache downloaded source files",
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
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    args.output_dir.mkdir(parents=True, exist_ok=True)

    if args.parquet_format == "v1":
        logger.info(
            "Using Parquet v1 (backward compat). "
            "For smaller files, re-run without --parquet-format or use: --parquet-format v2"
        )

    with tempfile.TemporaryDirectory() as tmp_dir:
        cache_dir = args.cache_dir or tmp_dir
        all_dfs: list[pd.DataFrame] = []

        # --- ATT&CK domains ---
        if "attack" in args.sources:
            attack_dfs = []
            for domain in args.domains:
                df = convert_domain(domain, args.output_dir, cache_dir, args.parquet_format)
                attack_dfs.append(df)

            if len(attack_dfs) > 1:
                attack_combined = pd.concat(attack_dfs, ignore_index=True).drop_duplicates()
                write_parquet(
                    attack_combined, args.output_dir / "attack-all.parquet", args.parquet_format
                )
                all_dfs.append(attack_combined)
            else:
                all_dfs.extend(attack_dfs)

        # --- CAPEC ---
        if "capec" in args.sources:
            from convert_capec import download_capec, extract_capec_triples

            capec_path = download_capec(cache_dir)
            triples = extract_capec_triples(capec_path)
            df = triples_to_dataframe(triples)
            write_parquet(df, args.output_dir / "capec.parquet", args.parquet_format)
            all_dfs.append(df)

        # --- CWE ---
        if "cwe" in args.sources:
            from convert_cwe import download_cwe, extract_cwe_triples

            cwe_path = download_cwe(cache_dir)
            triples = extract_cwe_triples(cwe_path)
            df = triples_to_dataframe(triples)
            write_parquet(df, args.output_dir / "cwe.parquet", args.parquet_format)
            all_dfs.append(df)

        # --- Combined (all sources) ---
        if not args.no_combined and len(all_dfs) > 1:
            combined = pd.concat(all_dfs, ignore_index=True).drop_duplicates()
            write_parquet(combined, args.output_dir / "combined.parquet", args.parquet_format)


if __name__ == "__main__":
    main()
