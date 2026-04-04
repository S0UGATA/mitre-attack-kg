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
- cve
- cpe
- d3fend
- atlas
- car
- engage
- epss
- kev
- vulnrichment
- ghsa
- sigma
- exploitdb
- stix
- threat-intelligence
- triples
pretty_name: "Security Knowledge Graph Triples (ATT&CK / CAPEC / CWE / CVE / CPE / D3FEND / ATLAS / CAR / ENGAGE / EPSS / KEV / Vulnrichment / GHSA / Sigma / ExploitDB)"
size_categories:
- 1M<n<10M
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
- config_name: cve
  data_files:
  - split: train
    path: data/cve.parquet
- config_name: cpe
  data_files:
  - split: train
    path: data/cpe.parquet
- config_name: d3fend
  data_files:
  - split: train
    path: data/d3fend.parquet
- config_name: atlas
  data_files:
  - split: train
    path: data/atlas.parquet
- config_name: car
  data_files:
  - split: train
    path: data/car.parquet
- config_name: engage
  data_files:
  - split: train
    path: data/engage.parquet
- config_name: epss
  data_files:
  - split: train
    path: data/epss.parquet
- config_name: kev
  data_files:
  - split: train
    path: data/kev.parquet
- config_name: vulnrichment
  data_files:
  - split: train
    path: data/vulnrichment.parquet
- config_name: ghsa
  data_files:
  - split: train
    path: data/ghsa.parquet
- config_name: sigma
  data_files:
  - split: train
    path: data/sigma.parquet
- config_name: exploitdb
  data_files:
  - split: train
    path: data/exploitdb.parquet
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

# Security Knowledge Graph Triples

Security data from 15 sources represented as **Subject-Predicate-Object (SPO) triples** in Parquet format, ready for knowledge-graph construction, graph-ML, RAG pipelines, and threat-intelligence analysis.

Sources: [ATT&CK](https://attack.mitre.org/) · [CAPEC](https://capec.mitre.org/) · [CWE](https://cwe.mitre.org/) · [CVE](https://www.cve.org/) · [CPE](https://nvd.nist.gov/products/cpe) · [D3FEND](https://d3fend.mitre.org/) · [ATLAS](https://atlas.mitre.org/) · [CAR](https://car.mitre.org/) · [ENGAGE](https://engage.mitre.org/) · [EPSS](https://www.first.org/epss/) · [KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) · [Vulnrichment](https://github.com/cisagov/vulnrichment) · [GHSA](https://github.com/github/advisory-database) · [Sigma](https://github.com/SigmaHQ/sigma) · [ExploitDB](https://gitlab.com/exploit-database/exploitdb)

*Last updated: 2026-04-04T14:46:34Z*

## Quick Start

```python
from datasets import load_dataset

ds = load_dataset("s0u9ata/security-kg", "enterprise")
print(ds["train"][0])
# {'subject': 'T1059.001', 'predicate': 'rdf:type', 'object': 'Technique'}
```

## Configurations

| Config | Description | Est. Triples | Status |
|--------|-------------|-------------|--------|
| `enterprise` (default) | Enterprise ATT&CK | 42,041 | Current |
| `mobile` | Mobile ATT&CK | 5,307 | Current |
| `ics` | ICS ATT&CK | 3,756 | Current |
| `attack-all` | ATT&CK combined (deduplicated) | 49,622 | Current |
| `capec` | CAPEC attack patterns | 8,114 | Current |
| `cwe` | CWE weaknesses | 14,565 | Current |
| `cve` | CVE vulnerabilities | 3,544,309 | Current |
| `cpe` | CPE platform enumeration | 12,399,534 | Current |
| `d3fend` | D3FEND defensive techniques | 8,154 | Current |
| `atlas` | ATLAS AI/ML techniques | 1,420 | Current |
| `car` | CAR analytics | 1,617 | Current |
| `engage` | ENGAGE adversary engagement | 1,464 | Current |
| `epss` | EPSS exploit prediction scores | 649,650 | Current |
| `kev` | KEV known exploited vulns | 17,054 | Current |
| `vulnrichment` | CISA Vulnrichment (SSVC, CVSS, CWE enrichment) | 656,207 | Current |
| `ghsa` | GitHub Security Advisories | 327,142 | Current |
| `sigma` | Sigma detection rules | 32,750 | Current |
| `exploitdb` | ExploitDB public exploits | 346,303 | Current |
| `combined` | All sources merged (deduplicated) | 18,057,905 | Current |



## Knowledge Graph Structure

```
                          Campaign ── attributed-to ──▶ Group
                             │                            │
                        uses │                            │ uses
                             ▼                            │
                        Malware/Tool ── uses ──┐          │
                                               │          │
                                               ▼          ▼
                                        ┌──────────────────────┐
    Sub-technique ── subtechnique-of ──▶│                      │── belongs-to-tactic ──▶ Tactic
                                        │                      │
        Mitigation ── mitigates ───────▶│                      │
                                        │                      │
      DataComponent ── detects ────────▶│                      │
                                        │                      │
   Analytic (CAR) ── detects-technique ▶│                      │
           │                            │                      │
           │ maps-to-d3fend             │      TECHNIQUE       │
           ▼                            │                      │
   DefensiveTechnique ── counters ─────▶│                      │
       (D3FEND)                         │                      │
                                        │                      │
       SigmaRule ── detects-technique ─▶│                      │
                                        │                      │
EngagementActivity ── engages-technique▶│                      │
       (ENGAGE)                         │                      │
                                        │                      │
 ATLAS Technique ── related-attack-tech▶│                      │
                                        │                      │
  Attack Pattern ── maps-to-technique ─▶│                      │
       (CAPEC)                          └──────────────────────┘
           │
           ├── child-of ──▶ Attack Pattern (parent)
           │
           │ related-weakness ──▶ child-of ──▶ Weakness (parent)
           ▼
      ┌─────────────────┐  
      │                 │
      │  Weakness (CWE) │── related-attack-pattern ──▶ Attack Pattern (CAPEC)
      │                 │
      │                 │◀── related-weakness ──── KEV Entry
      │                 │
      │                 │◀── related-weakness ──── Advisory (GHSA)
      └────────┬────────┘
               ▲
               │ related-weakness
               │
      ┌────────┴────────┐
      │                 │◀── related-cve ────── SigmaRule
      │                 │
      │  Vulnerability  │◀── related-cve ────── Advisory (GHSA)
      │     (CVE)       │
      │                 │◀── exploits-cve ───── Exploit (ExploitDB)
      │                 │
      │                 │◀── epss-score ─────── EPSS Score
      │                 │
      │                 │◀── ssvc-*/adp-* ───── Vulnrichment
      └────────┬────────┘
               │ affects-cpe
               ▼
        ┌──────────────┐
        │   Platform   │
        │    (CPE)     │
        └──────────────┘
```

## Schema

Each row is a single triple with three string columns:

| Column | Description | Examples |
|--------|-------------|----------|
| `subject` | Entity ID | `T1059.001`, `G0016`, `CAPEC-66`, `CWE-79`, `CVE-2024-1234`, `cpe:2.3:a:apache:httpd:*`, `D3-FE`, `AML.T0000`, `CAR-2024-01-001`, `EAC0001`, `GHSA-xxxx-yyyy-zzzz`, `EDB-16929` |
| `predicate` | Property name or relationship type | `rdf:type`, `name`, `uses`, `mitigates`, `epss-score`, `counters`, `ssvc-exploitation`, `exploits-cve`, `detects-technique` |
| `object` | Value or target entity ID | `Technique`, `PowerShell`, `T1059`, `CWE-89`, `0.97500`, `SecurityAdvisory`, `SigmaRule`, `Exploit` |

## Predicate Reference

### ATT&CK Entity Properties

| Predicate | Description | Example object value |
|-----------|-------------|---------------------|
| `rdf:type` | Entity type | `Technique`, `Group`, `Malware`, `Tool`, `Tactic`, `Mitigation`, `Campaign`, `DataSource`, `DataComponent` |
| `name` | Display name | `PowerShell` |
| `description` | Full description text | `Adversaries may abuse PowerShell...` |
| `platform` | Applicable platform | `Windows`, `Linux`, `macOS` |
| `domain` | ATT&CK domain | `enterprise-attack` |
| `alias` | Alternative name | `Cozy Bear` |
| `is-subtechnique` | Whether entity is a sub-technique | `True`, `False` |
| `belongs-to-tactic` | Tactic ATT&CK ID | `TA0002` |
| `shortname` | Tactic shortname | `credential-access` |
| `url` | ATT&CK website URL | `https://attack.mitre.org/techniques/T1059/001` |
| `created` / `modified` | Timestamps | `2020-01-14 17:18:32...` |

### ATT&CK Relationship Predicates

| Predicate | Typical subject / object | Example |
|-----------|--------------------------|---------|
| `uses` | Group/Campaign/Software / Technique | `G0016 / T1059.001` |
| `mitigates` | Mitigation / Technique | `M1049 / T1059.001` |
| `subtechnique-of` | Sub-technique / Parent technique | `T1059.001 / T1059` |
| `detects` | DataComponent / Technique | `DC0001 / T1059.001` |
| `attributed-to` | Campaign / Group | `C0018 / G0016` |

### CAPEC Predicates

| Predicate | Description | Example object value |
|-----------|-------------|---------------------|
| `rdf:type` | `AttackPattern` | `AttackPattern` |
| `name` / `description` | Display name / full text | `SQL Injection` |
| `abstraction` / `status` | Level / status | `Standard`, `Stable` |
| `likelihood` / `severity` | Attack likelihood / severity | `High` |
| `child-of` | Parent attack pattern | `CAPEC-248` |
| `related-weakness` | Related CWE | `CWE-89` |
| `maps-to-technique` | Mapped ATT&CK technique | `T1190.002` |

### CWE Predicates

| Predicate | Description | Example object value |
|-----------|-------------|---------------------|
| `rdf:type` | `Weakness` | `Weakness` |
| `name` / `description` | Display name / full text | `Cross-site Scripting (XSS)` |
| `abstraction` / `status` | Level / status | `Base`, `Stable` |
| `likelihood-of-exploit` | Exploitation likelihood | `High` |
| `child-of` | Parent weakness | `CWE-74` |
| `related-attack-pattern` | Related CAPEC | `CAPEC-86` |
| `platform` | Applicable platform | `JavaScript` |
| `consequence-scope` / `consequence-impact` | Impact | `Confidentiality`, `Read Data` |
| `introduction-phase` | Introduction phase | `Implementation` |

### CVE Predicates

| Predicate | Description | Example object value |
|-----------|-------------|---------------------|
| `rdf:type` | `Vulnerability` | `Vulnerability` |
| `state` | CVE state | `PUBLISHED` |
| `description` | English description | `A remote code execution...` |
| `date-published` / `date-updated` | Timestamps | `2024-01-15T00:00:00.000Z` |
| `assigner` | Assigning organization | `microsoft` |
| `vendor` / `product` | Affected vendor/product | `Microsoft`, `Windows` |
| `affects-cpe` | Affected CPE string | `cpe:2.3:o:microsoft:windows_10:*` |
| `platform` | Affected platform | `x64` |
| `related-weakness` | Related CWE | `CWE-79` |
| `cvss-base-score` / `cvss-severity` | CVSS metrics | `9.8`, `CRITICAL` |

### CPE Predicates

| Predicate | Description | Example object value |
|-----------|-------------|---------------------|
| `rdf:type` | `Platform` | `Platform` |
| `part` | CPE part type | `application`, `operating_system`, `hardware` |
| `vendor` / `product` / `version` | Components | `apache`, `httpd`, `2.4.51` |
| `title` | English display name | `Apache HTTP Server 2.4.51` |
| `created` / `modified` | Timestamps | `2021-10-07` |

### D3FEND Predicates

| Predicate | Description | Example object value |
|-----------|-------------|---------------------|
| `rdf:type` | `DefensiveTechnique` or `OffensiveTechnique` | `DefensiveTechnique` |
| `name` / `definition` | Display name / definition | `File Encryption` |
| `synonym` | Alternative name | `Disk Encryption` |
| `child-of` | Parent technique | `PlatformHardening` |
| `counters` | Countered offensive technique | `T1059` |

### ATLAS Predicates

| Predicate | Description | Example object value |
|-----------|-------------|---------------------|
| `rdf:type` | `Tactic`, `Technique`, `CaseStudy`, `Mitigation` | `Technique` |
| `name` / `description` | Display name / full text | `ML Supply Chain Compromise` |
| `maturity` | Technique maturity | `Reviewed` |
| `belongs-to-tactic` | Parent tactic | `AML.TA0001` |
| `subtechnique-of` | Parent technique | `AML.T0000` |
| `related-attack-technique` | Linked ATT&CK technique | `T1195` |
| `related-attack-tactic` | Linked ATT&CK tactic | `TA0001` |
| `uses-technique` | Case study technique | `AML.T0000` |
| `mitigates` | Mitigated technique | `AML.T0000` |

### CAR Predicates

| Predicate | Description | Example object value |
|-----------|-------------|---------------------|
| `rdf:type` | `Analytic` | `Analytic` |
| `title` / `description` | Analytic name / full text | `Suspicious PowerShell Commands` |
| `platform` | Applicable platform | `Windows` |
| `information-domain` | Information domain | `Host` |
| `analytic-type` | Type of analytic | `Situational Awareness` |
| `detects-technique` | Detected ATT&CK technique | `T1059` |
| `detects-subtechnique` | Detected subtechnique | `T1059.001` |
| `covers-tactic` | Covered ATT&CK tactic | `Execution` |
| `maps-to-d3fend` | Linked D3FEND technique | `D3-PSA` |

### ENGAGE Predicates

| Predicate | Description | Example object value |
|-----------|-------------|---------------------|
| `rdf:type` | `EngagementActivity` or `AdversaryVulnerability` | `EngagementActivity` |
| `name` / `description` | Display name / full text | `Software Manipulation` |
| `engages-technique` | Engaged ATT&CK technique | `T1001` |
| `exploits-vulnerability-of` | Exploited ATT&CK technique | `T1001` |
| `addresses-vulnerability` | Addressed adversary vulnerability | `EAV0001` |

### EPSS Predicates

| Predicate | Description | Example object value |
|-----------|-------------|---------------------|
| `epss-score` | Exploit probability (0-1) | `0.97500` |
| `epss-percentile` | Score percentile (0-1) | `0.99900` |

### KEV Predicates

| Predicate | Description | Example object value |
|-----------|-------------|---------------------|
| `rdf:type` | `KnownExploitedVulnerability` | `KnownExploitedVulnerability` |
| `kev-vendor` / `kev-product` | Affected vendor/product | `Microsoft`, `Windows` |
| `kev-name` / `kev-description` | Vulnerability name/description | `Windows Privilege Escalation` |
| `kev-date-added` / `kev-due-date` | Dates | `2024-01-15` |
| `kev-required-action` | Required remediation action | `Apply updates per vendor instructions.` |
| `kev-ransomware-use` | Ransomware campaign use | `Known`, `Unknown` |
| `related-weakness` | Related CWE | `CWE-269` |

### Vulnrichment Predicates

| Predicate | Description | Example object value |
|-----------|-------------|---------------------|
| `ssvc-exploitation` | SSVC exploitation status | `active`, `poc`, `none` |
| `ssvc-automatable` | Whether exploitation is automatable | `yes`, `no` |
| `ssvc-technical-impact` | Technical impact level | `total`, `partial` |
| `adp-cvss-base-score` | CISA-analyzed CVSS base score | `9.8` |
| `adp-cvss-severity` | CISA-analyzed CVSS severity | `CRITICAL` |
| `adp-related-weakness` | CISA-assigned CWE | `CWE-79` |
| `adp-affects-cpe` | CISA-assigned CPE | `cpe:2.3:o:microsoft:windows_10:*` |

### GHSA Predicates

| Predicate | Description | Example object value |
|-----------|-------------|---------------------|
| `rdf:type` | `SecurityAdvisory` | `SecurityAdvisory` |
| `summary` | Advisory summary | `XSS vulnerability in example-package` |
| `date-published` / `date-modified` | Timestamps | `2024-01-15T00:00:00Z` |
| `severity` | Severity level | `HIGH`, `MODERATE`, `LOW`, `CRITICAL` |
| `related-cve` | Associated CVE | `CVE-2024-1234` |
| `related-weakness` | Associated CWE | `CWE-79` |
| `cvss-vector` | CVSS v3 vector string | `CVSS:3.1/AV:N/AC:L/...` |
| `affects-package` | Affected package (ecosystem/name) | `npm/example-package` |
| `fixed-in:<pkg>` | Fix version for a package | `2.0.1` |

### Sigma Predicates

| Predicate | Description | Example object value |
|-----------|-------------|---------------------|
| `rdf:type` | `SigmaRule` | `SigmaRule` |
| `title` / `description` | Rule name / full text | `Suspicious PowerShell Download` |
| `status` | Rule maturity | `stable`, `test`, `experimental` |
| `level` | Detection severity | `critical`, `high`, `medium`, `low`, `informational` |
| `author` / `date` | Rule author / creation date | `Security Researcher`, `2024-01-15` |
| `logsource-category` | Log source category | `process_creation`, `network_connection` |
| `logsource-product` | Log source product | `windows`, `linux` |
| `logsource-service` | Log source service | `sshd`, `sysmon` |
| `detects-technique` | Detected ATT&CK technique | `T1059.001` |
| `related-cve` | Related CVE | `CVE-2024-1234` |

### ExploitDB Predicates

| Predicate | Description | Example object value |
|-----------|-------------|---------------------|
| `rdf:type` | `Exploit` | `Exploit` |
| `description` | Exploit description | `Apache HTTP Server RCE` |
| `date-published` | Publication date | `2024-01-15` |
| `author` | Exploit author | `Metasploit` |
| `exploit-type` | Exploit category | `remote`, `local`, `dos`, `webapps` |
| `platform` | Target platform | `linux`, `windows`, `aix` |
| `verified` | Verified by OffSec | `True` |
| `exploits-cve` | Exploited CVE | `CVE-2024-1234` |

## Dataset Creation

### Source Data

| Source | Feed | Format |
|--------|------|--------|
| ATT&CK | [`mitre-attack/attack-stix-data`](https://github.com/mitre-attack/attack-stix-data) | STIX 2.0 JSON |
| CAPEC | [`capec_latest.xml`](https://capec.mitre.org/data/xml/capec_latest.xml) | XML |
| CWE | [`cwec_latest.xml.zip`](https://cwe.mitre.org/data/xml/cwec_latest.xml.zip) | XML (ZIP) |
| CVE | [`CVEProject/cvelistV5`](https://github.com/CVEProject/cvelistV5/releases) | JSON 5.x (ZIP) |
| CPE | [`nvdcpe-2.0.tar.gz`](https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz) | JSON (tar.gz) |
| D3FEND | [`d3fend.json`](https://d3fend.mitre.org/ontologies/d3fend.json) | JSON-LD |
| ATLAS | [`ATLAS.yaml`](https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml) | YAML |
| CAR | [`mitre-attack/car`](https://github.com/mitre-attack/car) | YAML (ZIP) |
| ENGAGE | [`attack_mapping.json`](https://raw.githubusercontent.com/mitre/engage/main/Data/json/attack_mapping.json) | JSON |
| EPSS | [`epss_scores-current.csv.gz`](https://epss.cyentia.com/epss_scores-current.csv.gz) | CSV (gzip) |
| KEV | [`known_exploited_vulnerabilities.json`](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | JSON |
| Vulnrichment | [`cisagov/vulnrichment`](https://github.com/cisagov/vulnrichment) | JSON 5.x (ZIP) |
| GHSA | [`github/advisory-database`](https://github.com/github/advisory-database) | OSV JSON (ZIP) |
| Sigma | [`SigmaHQ/sigma`](https://github.com/SigmaHQ/sigma/releases) | YAML (ZIP) |
| ExploitDB | [`files_exploits.csv`](https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv) | CSV |

### Conversion Pipeline

The converter downloads source data, extracts entity property triples and relationship triples, and writes them as Parquet files. The source code and full documentation are at:

**[github.com/S0UGATA/security-kg](https://github.com/S0UGATA/security-kg)**

To regenerate or update this dataset:

```bash
git clone https://github.com/S0UGATA/security-kg.git
cd security-kg
pip install -r requirements.txt
python src/convert.py
```

This produces fresh Parquet files in `output/` from the latest data across all 15 sources.

## Use Cases

- **Knowledge Graph Construction**: Load triples into Neo4j, RDFLib, or NetworkX for graph queries
- **Graph ML**: Train graph neural networks (GNNs) on security data structure for link prediction
- **RAG / LLM Grounding**: Use triples as structured context for retrieval-augmented generation
- **Threat Intelligence**: Query relationships between groups, techniques, vulnerabilities, and mitigations
- **Vulnerability Prioritization**: Combine CVE, EPSS, and KEV data for risk-based prioritization
- **Security Automation**: Programmatically map detections to techniques to tactics

## Example Queries

### Enterprise ATT&CK

```python
from datasets import load_dataset

ds = load_dataset("s0u9ata/security-kg", "enterprise")
df = ds["train"].to_pandas()

# What techniques does APT29 (G0016) use?
apt29_techniques = df[(df.subject == "G0016") & (df.predicate == "uses")].object.tolist()

# What mitigates PowerShell (T1059.001)?
mitigations = df[(df.predicate == "mitigates") & (df.object == "T1059.001")].subject.tolist()
```

### CVE + EPSS + KEV (Vulnerability Prioritization)

```python
# Load CVE and EPSS data
cve = load_dataset("s0u9ata/security-kg", "cve")["train"].to_pandas()
epss = load_dataset("s0u9ata/security-kg", "epss")["train"].to_pandas()
kev = load_dataset("s0u9ata/security-kg", "kev")["train"].to_pandas()

# High EPSS scores (likely to be exploited)
high_epss = epss[(epss.predicate == "epss-score") & (epss.object.astype(float) > 0.5)]

# Known exploited vulnerabilities
kev_cves = kev[kev.predicate == "rdf:type"].subject.tolist()

# CVEs with critical CVSS scores
critical = cve[(cve.predicate == "cvss-severity") & (cve.object == "CRITICAL")]
```

### D3FEND (Defensive Mapping)

```python
ds = load_dataset("s0u9ata/security-kg", "d3fend")
df = ds["train"].to_pandas()

# What defensive techniques counter a specific ATT&CK technique?
counters = df[(df.predicate == "counters") & (df.object == "T1059")].subject.tolist()

# All defensive techniques
defenses = df[(df.predicate == "rdf:type") & (df.object == "DefensiveTechnique")].subject.tolist()
```

### CAPEC → CWE → CVE (Attack Chain)

```python
capec = load_dataset("s0u9ata/security-kg", "capec")["train"].to_pandas()
cve = load_dataset("s0u9ata/security-kg", "cve")["train"].to_pandas()

# Find CWEs related to SQL Injection (CAPEC-66)
cwe_ids = capec[(capec.subject == "CAPEC-66") & (capec.predicate == "related-weakness")].object.tolist()

# Find CVEs with those CWEs
for cwe_id in cwe_ids:
    related_cves = cve[(cve.predicate == "related-weakness") & (cve.object == cwe_id)].subject.unique()
    print(f"{cwe_id}: {len(related_cves)} CVEs")
```

### CAR Analytics

```python
ds = load_dataset("s0u9ata/security-kg", "car")
df = ds["train"].to_pandas()

# Which analytics detect T1059 (Command and Scripting Interpreter)?
analytics = df[(df.predicate == "detects-technique") & (df.object == "T1059")].subject.tolist()

# Analytics with D3FEND mappings
d3fend_mapped = df[df.predicate == "maps-to-d3fend"]
```

## License

Apache 2.0 -- same as the underlying source data.
