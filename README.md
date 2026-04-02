# mitre-attack-kg

[![CI](https://github.com/S0UGATA/mitre-attack-kg/actions/workflows/ci.yml/badge.svg)](https://github.com/S0UGATA/mitre-attack-kg/actions/workflows/ci.yml)
[![Dataset Update](https://github.com/S0UGATA/mitre-attack-kg/actions/workflows/update-dataset.yml/badge.svg)](https://github.com/S0UGATA/mitre-attack-kg/actions/workflows/update-dataset.yml)
[![HuggingFace](https://img.shields.io/badge/dataset-HuggingFace-yellow)](https://huggingface.co/datasets/s0u9ata/mitre-attack-kg)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE)

Convert [MITRE ATT&CK](https://attack.mitre.org/), [CAPEC](https://capec.mitre.org/), and [CWE](https://cwe.mitre.org/) data into **Subject-Predicate-Object (SPO) knowledge-graph triples** in Parquet format.

## Data Flow

```mermaid
---
config:
  layout: dagre
  theme: neo
---
flowchart LR
 subgraph src["Source Data"]
        STIX["ATT&CK STIX JSON"]
        CXML["CAPEC XML"]
        WXML["CWE XML"]
  end
 subgraph out["SPO Triples · Parquet"]
        ATK["enterprise / mobile / ics / attack-all"]
        CAP["capec"]
        CW["cwe"]
        CMB["combined"]
  end
    STIX --> CONV["convert.py"]
    CXML --> CONV
    WXML --> CONV
    CONV --> ATK & CAP & CW --> CMB
    out --> HF["HuggingFace Hub"]

    style STIX fill:#dbeafe,stroke:#3b82f6
    style CXML fill:#fef3c7,stroke:#f59e0b
    style WXML fill:#fce7f3,stroke:#ec4899
    style CONV fill:#f3f4f6,stroke:#6b7280
    style ATK fill:#dbeafe,stroke:#3b82f6
    style CAP fill:#fef3c7,stroke:#f59e0b
    style CW fill:#fce7f3,stroke:#ec4899
    style CMB fill:#f3f4f6,stroke:#6b7280
    style HF fill:#d1fae5,stroke:#10b981
```

## Knowledge Graph Structure

```mermaid
---
config:
  layout: dagre
  theme: neo
---
graph LR
    C[Campaign]:::attack -->|attributed-to| G[Group]:::attack
    G -->|uses| SW[Malware / Tool]:::attack
    C -->|uses| T[Technique]:::attack
    G -->|uses| T
    SW -->|uses| T
    ST[Sub-technique]:::attack -->|subtechnique-of| T
    MIT[Mitigation]:::attack -->|mitigates| T
    DC[DataComponent]:::attack -->|detects| T
    T -->|belongs-to-tactic| TAC[Tactic]:::attack
    AP[Attack Pattern]:::capec -->|maps-to-technique| T
    AP -->|related-weakness| W[Weakness]:::cwe
    W -->|related-attack-pattern| AP
    classDef attack fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef capec fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef cwe fill:#fce7f3,stroke:#ec4899,color:#831843
```

> Legend: <span style="color:#3b82f6">**Blue** = ATT&CK</span> · <span style="color:#f59e0b">**Amber** = CAPEC</span> · <span style="color:#ec4899">**Pink** = CWE</span> · Attack Patterns and Weaknesses also form parent–child hierarchies via **child-of** edges (not shown).

## Usage

```bash
# Install dependencies
pip install -r requirements.txt

# Convert everything (ATT&CK + CAPEC + CWE) and produce combined.parquet
python convert.py

# Convert only ATT&CK
python convert.py --sources attack

# Convert a single ATT&CK domain
python convert.py --sources attack --domains enterprise

# Convert only CAPEC and CWE (skip ATT&CK)
python convert.py --sources capec cwe

# Cache downloaded source files for repeated runs
python convert.py --cache-dir /tmp

# Run individual converters standalone
python convert_attack.py
python convert_capec.py
python convert_cwe.py

# Use Parquet v1 format for backward compatibility (default is v2)
python convert.py --parquet-format v1
```

Output goes to `output/`:

| File | Source | Triples |
|------|--------|---------|
| `enterprise.parquet` | ATT&CK Enterprise | 42,041 |
| `mobile.parquet` | ATT&CK Mobile | 5,307 |
| `ics.parquet` | ATT&CK ICS | 3,756 |
| `attack-all.parquet` | ATT&CK combined (deduplicated) | 49,622 |
| `capec.parquet` | CAPEC attack patterns | 8,114 |
| `cwe.parquet` | CWE weaknesses | 14,565 |
| `combined.parquet` | All sources merged (deduplicated) | 71,531 |

Downloaded source files are automatically cleaned up after conversion. Use `--cache-dir` to persist them for repeated runs.

## Tests

```bash
# Unit tests (no network access required)
python -m pytest tests/test_convert_attack.py tests/test_convert_capec.py tests/test_convert_cwe.py -v

# Integration tests (downloads real ATT&CK data)
python -m pytest tests/test_integration.py -v

# All tests
python -m pytest tests/ -v
```

## HuggingFace Dataset

The dataset is published at [s0u9ata/mitre-attack-kg](https://huggingface.co/datasets/s0u9ata/mitre-attack-kg) on HuggingFace Hub and auto-updated weekly via GitHub Actions.

See the [dataset card](hf_dataset/README.md) for schema details, example queries, and usage with the `datasets` library.

## License

Apache 2.0
