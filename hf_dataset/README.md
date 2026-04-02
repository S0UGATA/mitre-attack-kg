---
language:
- en
license: apache-2.0
task_categories:
- graph-ml
tags:
- knowledge-graph
- cybersecurity
- mitre-attack
- capec
- cwe
- stix
- threat-intelligence
- triples
pretty_name: "MITRE ATT&CK / CAPEC / CWE Knowledge Graph Triples"
size_categories:
- 10K<n<100K
configs:
- config_name: enterprise
  data_files:
  - split: train
    path: data/enterprise.parquet
  default: true
- config_name: mobile
  data_files:
  - split: train
    path: data/mobile.parquet
- config_name: ics
  data_files:
  - split: train
    path: data/ics.parquet
- config_name: attack-all
  data_files:
  - split: train
    path: data/attack-all.parquet
- config_name: capec
  data_files:
  - split: train
    path: data/capec.parquet
- config_name: cwe
  data_files:
  - split: train
    path: data/cwe.parquet
- config_name: combined
  data_files:
  - split: train
    path: data/combined.parquet
dataset_info:
  features:
  - name: subject
    dtype: string
  - name: predicate
    dtype: string
  - name: object
    dtype: string
---

# MITRE ATT&CK Knowledge Graph Triples

[MITRE ATT&CK](https://attack.mitre.org/), [CAPEC](https://capec.mitre.org/), and [CWE](https://cwe.mitre.org/) data represented as **Subject-Predicate-Object (SPO) triples** in Parquet format, ready for knowledge-graph construction, graph-ML, RAG pipelines, and threat-intelligence analysis.

## Quick Start

```python
from datasets import load_dataset

ds = load_dataset("s0u9ata/mitre-attack-kg", "enterprise")
print(ds["train"][0])
# {'subject': 'T1059.001', 'predicate': 'rdf:type', 'object': 'Technique'}
```

## Configurations

| Config | Description | Triples |
|--------|-------------|---------|
| `enterprise` (default) | Enterprise ATT&CK | 42,041 |
| `mobile` | Mobile ATT&CK | 5,307 |
| `ics` | ICS ATT&CK | 3,756 |
| `attack-all` | ATT&CK combined (deduplicated) | 49,622 |
| `capec` | CAPEC attack patterns | 8,114 |
| `cwe` | CWE weaknesses | 14,565 |
| `combined` | All sources merged (deduplicated) | 71,531 |

*Counts as of 2026-04-02T20:36:34Z. Regenerate from [source](https://github.com/S0UGATA/mitre-attack-kg) for the latest data.*

## Knowledge Graph Structure

```
                                         ATT&CK
                                         ──────

   Campaign ───── attributed-to ─────▶ Group
       │                                  │
       │                                  │
       │ uses                             │ uses
       │                                  │
       ▼                                  ▼
   Malware/Tool ──────── uses ────────▶ Technique ──── belongs-to-tactic ────▶ Tactic
                                          ▲  ▲  ▲
                                          │  │  │
         Sub-technique ──subtechnique-of──┘  │  └── detects ── DataComponent
                                             │
                   Mitigation ── mitigates ──┘


                              CAPEC                CWE
                              ─────                ───

                    ╭── child-of ──╮          ╭── child-of ──╮
                    ╰─▶ Attack Pattern        ╰─▶ Weakness


                                    Cross-source
                                    ────────────

   Attack Pattern ── maps-to-technique ──────────────▶ Technique        (CAPEC → ATT&CK)

   Attack Pattern ── related-weakness ───────────────▶ Weakness         (CAPEC → CWE)

   Weakness ── related-attack-pattern ───────────────▶ Attack Pattern   (CWE → CAPEC)
```

## Schema

Each row is a single triple with three string columns:

| Column | Description | Examples |
|--------|-------------|----------|
| `subject` | Entity ID | `T1059.001`, `G0016`, `CAPEC-66`, `CWE-79` |
| `predicate` | Property name or relationship type | `rdf:type`, `name`, `uses`, `mitigates` |
| `object` | Value or target entity ID | `Technique`, `PowerShell`, `T1059`, `CWE-89` |

## Predicate Reference

### Entity properties (from STIX object fields)

| Predicate | Description | Example object value |
|-----------|-------------|---------------------|
| `rdf:type` | Entity type | `Technique`, `Group`, `Malware`, `Tool`, `Tactic`, `Mitigation`, `Campaign`, `DataSource`, `DataComponent` |
| `name` | Display name | `PowerShell` |
| `description` | Full description text | `Adversaries may abuse PowerShell...` |
| `platform` | Applicable platform (one triple per platform) | `Windows`, `Linux`, `macOS` |
| `domain` | ATT&CK domain | `enterprise-attack` |
| `alias` | Alternative name (excludes primary name) | `Cozy Bear` |
| `is-subtechnique` | Whether entity is a sub-technique | `True`, `False` |
| `belongs-to-tactic` | Tactic ATT&CK ID from kill chain phases | `TA0002`, `TA0003` |
| `shortname` | Tactic shortname (on Tactic entities) | `credential-access` |
| `url` | ATT&CK website URL | `https://attack.mitre.org/techniques/T1059/001` |
| `created` | Creation timestamp | `2020-01-14 17:18:32...` |
| `modified` | Last modification timestamp | `2024-06-01 12:00:00...` |
| `revoked` | Whether entity is revoked | `true` |
| `deprecated` | Whether entity is deprecated | `true` |

### ATT&CK relationship predicates (from STIX relationship objects)

| Predicate | Typical subject / object | Example |
|-----------|--------------------------|---------|
| `uses` | Group/Campaign/Software / Technique | `G0016 / T1059.001` |
| `mitigates` | Mitigation / Technique | `M1049 / T1059.001` |
| `subtechnique-of` | Sub-technique / Parent technique | `T1059.001 / T1059` |
| `detects` | DataComponent / Technique | `DC0001 / T1059.001` |
| `attributed-to` | Campaign / Group | `C0018 / G0016` |
| `revoked-by` | Old entity / Replacement entity | `T1234 / T5678` |
| `targets` | Technique / Asset (ICS) | `T0800 / A0001` |

### CAPEC properties and relationships

| Predicate | Description | Example object value |
|-----------|-------------|---------------------|
| `rdf:type` | Always `AttackPattern` | `AttackPattern` |
| `name` | Display name | `SQL Injection` |
| `description` | Full description text | `An attacker exploits...` |
| `abstraction` | Abstraction level | `Meta`, `Standard`, `Detailed` |
| `status` | Pattern status | `Stable`, `Draft` |
| `likelihood` | Likelihood of attack | `High`, `Medium`, `Low` |
| `severity` | Typical severity | `High`, `Medium`, `Low` |
| `child-of` | Parent attack pattern | `CAPEC-248` |
| `related-weakness` | Related CWE weakness | `CWE-89` |
| `maps-to-technique` | Mapped ATT&CK technique | `T1190.002` |
| `consequence-scope` | Impact scope | `Confidentiality` |
| `consequence-impact` | Impact type | `Read Data` |

### CWE properties and relationships

| Predicate | Description | Example object value |
|-----------|-------------|---------------------|
| `rdf:type` | Always `Weakness` | `Weakness` |
| `name` | Display name | `Cross-site Scripting (XSS)` |
| `description` | Full description text | `The product does not...` |
| `abstraction` | Abstraction level | `Base`, `Class`, `Variant` |
| `status` | Weakness status | `Stable`, `Draft` |
| `likelihood-of-exploit` | Exploitation likelihood | `High`, `Medium`, `Low` |
| `child-of` | Parent weakness | `CWE-74` |
| `related-attack-pattern` | Related CAPEC pattern | `CAPEC-86` |
| `platform` | Applicable platform | `JavaScript`, `Web Based` |
| `consequence-scope` | Impact scope | `Confidentiality`, `Integrity` |
| `consequence-impact` | Impact type | `Execute Unauthorized Code or Commands` |
| `introduction-phase` | Introduction phase | `Implementation`, `Design` |

## Dataset Creation

### Source Data

| Source | Feed | Last Updated |
|--------|------|--------------|
| ATT&CK | [`mitre-attack/attack-stix-data`](https://github.com/mitre-attack/attack-stix-data/commit/70987bc82ae85f594471c6ca532235c388f7a368) | 2025-12-23T18:37:51Z |
| CAPEC | [`capec_latest.xml`](https://capec.mitre.org/data/xml/capec_latest.xml) | 2023-01-24T18:32:31Z |
| CWE | [`cwec_latest.xml.zip`](https://cwe.mitre.org/data/xml/cwec_latest.xml.zip) | 2026-01-21T10:22:51Z |

### Conversion Pipeline

The converter downloads source data, extracts entity property triples and relationship triples, and writes them as Parquet files. The source code and full documentation are at:

**[github.com/S0UGATA/mitre-attack-kg](https://github.com/S0UGATA/mitre-attack-kg)**

To regenerate or update this dataset:

```bash
git clone https://github.com/S0UGATA/mitre-attack-kg.git
cd mitre-attack-kg
pip install -r requirements.txt
python convert.py
```

This produces fresh Parquet files in `output/` from the latest ATT&CK, CAPEC, and CWE data.

## Use Cases

- **Knowledge Graph Construction**: Load triples into Neo4j, RDFLib, or NetworkX for graph queries
- **Graph ML**: Train graph neural networks (GNNs) on ATT&CK structure for link prediction
- **RAG / LLM Grounding**: Use triples as structured context for retrieval-augmented generation
- **Threat Intelligence**: Query relationships between groups, techniques, and mitigations
- **Security Automation**: Programmatically map detections to techniques to tactics

## Example Queries

### Enterprise

```python
from datasets import load_dataset

ds = load_dataset("s0u9ata/mitre-attack-kg", "enterprise")
df = ds["train"].to_pandas()

# What techniques does APT29 (G0016) use?
apt29_techniques = df[(df.subject == "G0016") & (df.predicate == "uses")].object.tolist()

# What mitigates PowerShell (T1059.001)?
mitigations = df[(df.predicate == "mitigates") & (df.object == "T1059.001")].subject.tolist()

# All sub-techniques of Command and Scripting Interpreter (T1059)
subtechs = df[(df.predicate == "subtechnique-of") & (df.object == "T1059")].subject.tolist()
```

### Mobile

```python
ds = load_dataset("s0u9ata/mitre-attack-kg", "mobile")
df = ds["train"].to_pandas()

# All mobile malware families
mobile_malware = df[(df.predicate == "rdf:type") & (df.object == "Malware")].subject.tolist()

# What techniques does Pegasus (S0316) use?
pegasus_techs = df[(df.subject == "S0316") & (df.predicate == "uses")].object.tolist()

# Mobile mitigations
mobile_mitigations = df[(df.predicate == "rdf:type") & (df.object == "Mitigation")].subject.tolist()
```

### ICS

```python
ds = load_dataset("s0u9ata/mitre-attack-kg", "ics")
df = ds["train"].to_pandas()

# All ICS techniques
ics_techniques = df[(df.predicate == "rdf:type") & (df.object == "Technique")].subject.tolist()

# What techniques does Stuxnet (S0603) use?
stuxnet_techs = df[(df.subject == "S0603") & (df.predicate == "uses")].object.tolist()

# Which groups target ICS?
ics_groups = df[(df.predicate == "rdf:type") & (df.object == "Group")].subject.tolist()
```

### Cross-domain ATT&CK (attack-all)

```python
ds = load_dataset("s0u9ata/mitre-attack-kg", "attack-all")
df = ds["train"].to_pandas()

# Total techniques across all ATT&CK domains
all_techniques = df[(df.predicate == "rdf:type") & (df.object == "Technique")].subject.unique()
print(f"{len(all_techniques)} unique techniques across enterprise, mobile, and ICS")

# Find all entity types and their counts
type_counts = df[df.predicate == "rdf:type"].object.value_counts()
print(type_counts)

# All groups and the techniques they use, across domains
group_uses = df[(df.predicate == "uses") & df.subject.str.startswith("G")]
print(f"{group_uses.subject.nunique()} groups using {group_uses.object.nunique()} techniques")
```

### CAPEC

```python
ds = load_dataset("s0u9ata/mitre-attack-kg", "capec")
df = ds["train"].to_pandas()

# All attack patterns
patterns = df[(df.predicate == "rdf:type") & (df.object == "AttackPattern")].subject.tolist()

# Which CWE weaknesses are related to SQL Injection (CAPEC-66)?
cwe_links = df[(df.subject == "CAPEC-66") & (df.predicate == "related-weakness")].object.tolist()

# Which ATT&CK techniques does CAPEC-66 map to?
techs = df[(df.subject == "CAPEC-66") & (df.predicate == "maps-to-technique")].object.tolist()
```

### CWE

```python
ds = load_dataset("s0u9ata/mitre-attack-kg", "cwe")
df = ds["train"].to_pandas()

# All weaknesses
weaknesses = df[(df.predicate == "rdf:type") & (df.object == "Weakness")].subject.tolist()

# What CAPEC patterns relate to XSS (CWE-79)?
capec_links = df[(df.subject == "CWE-79") & (df.predicate == "related-attack-pattern")].object.tolist()

# High-likelihood weaknesses
high_risk = df[(df.predicate == "likelihood-of-exploit") & (df.object == "High")].subject.tolist()
```

## License

Apache 2.0 -- same as the underlying MITRE ATT&CK data.
