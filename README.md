# An Integrated System for Malware and Network Intrusion Detection and Analysis

> BSc (Hons) Cyber Security Dissertation Project

An end-to-end detection platform that integrates **network traffic analysis** (Snort IDS), **malware static analysis** (YARA + PE feature extraction), and **dynamic sandbox analysis** (CAPEv2) into a unified detection and correlation pipeline, with a **D3.js Web dashboard** for visualization.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Project Structure](#project-structure)
- [Core Modules](#core-modules)
- [Usage](#usage)
  - [Quick Start (Synthetic Demo)](#quick-start-synthetic-demo)
  - [Real Dataset Analysis (MalwareBazaar)](#real-dataset-analysis-malwarebazaar)
  - [Dynamic Analysis (CAPEv2)](#dynamic-analysis-capev2)
  - [Network Traffic Analysis (Snort)](#network-traffic-analysis-snort)
  - [Correlation Engine](#correlation-engine)
  - [Web Dashboard](#web-dashboard)
- [Testing](#testing)
- [Datasets](#datasets)
- [Tools & Utilities](#tools--utilities)
- [Configuration](#configuration)
- [Evaluation](#evaluation)

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                     Orchestrator (orchestrator.py)                    │
│                                                                      │
│  ┌────────────┐ ┌────────────┐ ┌───────────────┐ ┌────────────────┐  │
│  │  Snort IDS │ │YARA Engine │ │Static Analyzer│ │ CAPEv2 Dynamic │  │
│  │  (WSL2)    │ │ (8 Rules)  │ │(Hash/PE/Str)  │ │   Sandbox      │  │
│  └─────┬──────┘ └─────┬──────┘ └──────┬────────┘ └───────┬────────┘  │
│        │              │               │                  │           │
│        └──────────────┼───────────────┼──────────────────┘           │
│                       │               │                              │
│  ┌────────────────────▼───────────────▼──────────────────────────┐   │
│  │     Correlation Engine (5D Weighted + Threat-Level Modulation) │   │
│  │  IP(0.25) + Domain(0.25) + Hash(0.30) + Behaviour(0.20)       │   │
│  │              × Time Proximity Boost (×1.3)                    │   │
│  └───────────────────────────┬───────────────────────────────────┘   │
│                              │                                       │
│  ┌───────────────────────────▼───────────────────────────────────┐   │
│  │                    SQLite Database                             │   │
│  │      alerts | samples | correlations | iocs                   │   │
│  └───────────────────────────┬───────────────────────────────────┘   │
└──────────────────────────────┼──────────────────────────────────────┘
                               │
                ┌──────────────▼──────────────┐
                │   Flask + D3.js Dashboard   │
                │   http://localhost:5000     │
                └─────────────────────────────┘
```

---

## Prerequisites

| Component | Version | Purpose |
|-----------|---------|---------|
| Python | 3.10+ | Core runtime |
| Conda/Miniconda | Latest | Environment management |
| WSL2 + Ubuntu 22.04 | Latest | Snort IDS runtime |
| Snort | 2.9.15 | Network traffic analysis |
| Hyper-V | Windows 11 | CAPEv2 VM hosting |

---

## Installation

### 1. Clone and Set Up Python Environment

```bash
# Create conda environment
conda create -n detection-system python=3.10 -y
conda activate detection-system

# Install Python dependencies
pip install -r requirements_pip.txt
```

### 2. Install Snort (WSL2 Ubuntu)

```bash
# Run the automated setup script
wsl -d Ubuntu-22.04 -u root -- bash tools/setup_wsl_snort.sh
```

### 3. Set Up CAPEv2 (Hyper-V VM)

See detailed instructions in `project_summary.md` Phase 7, or use the automated scripts:
```powershell
# 1. Enable Hyper-V (Admin PowerShell)
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All

# 2. Create VM (after reboot)
powershell -ExecutionPolicy Bypass -File vm_serve\create_hv_vm.ps1

# 3. Install Ubuntu, then SSH in and run:
sudo /opt/CAPEv2/installer/cape2.sh all cape
```

---

## Project Structure

```
Part-time/
│
├── src/                              # Core source code
│   ├── __init__.py                   # Package init
│   ├── config.py                     # Global configuration (paths, thresholds, weights)
│   ├── plugin_framework.py           # Extensible plugin base class (BaseAnalyzer)
│   ├── utils.py                      # Utility functions (hash, entropy, BFD, strings)
│   ├── static_analyzer.py            # Static feature analysis (hash, entropy, BFD, PE, strings)
│   ├── snort_wrapper.py              # Snort IDS wrapper (subprocess + alert parsing)
│   ├── yara_wrapper.py               # YARA rule matching engine
│   ├── dynamic_analyzer.py           # CAPEv2 sandbox integration (API + report parsing)
│   ├── correlation_engine.py         # 5-dimension weighted correlation engine
│   ├── database.py                   # SQLite persistence (alerts, samples, correlations, iocs)
│   └── orchestrator.py               # Main pipeline orchestrator
│
├── tests/                            # Unit tests (122 tests, 100% pass)
│   ├── test_utils.py                 # 27 tests — utility functions
│   ├── test_plugin_framework.py      # 18 tests — plugin registry & base class
│   ├── test_static_analyzer.py       # 19 tests — static analysis (incl. BFD)
│   ├── test_database.py              # 22 tests — database CRUD
│   ├── test_correlation_engine.py    # 18 tests — correlation matching
│   └── test_orchestrator.py          # 18 tests — orchestration pipeline
│
├── tools/                            # Utility scripts
│   ├── download_malwarebazaar.py     # MalwareBazaar daily batch PE downloader
│   ├── run_bazaar_analysis.py        # Static + YARA batch analysis (100 samples)
│   ├── import_cape_results.py        # CAPEv2 report downloader & DB importer
│   ├── run_snort_pcaps.py            # Snort analysis on CAPEv2 sandbox PCAPs
│   ├── run_correlation.py            # Cross-source correlation engine (v8)
│   ├── evaluate.py                   # Comprehensive performance evaluation
│   ├── integrate_snort_alerts.py     # Snort alert → SQLite integrator
│   ├── setup_wsl_snort.sh            # WSL2 + Snort automated installer
│   └── ...                           # Additional helper/debug scripts
│
├── dashboard/                        # Web visualization dashboard
│   ├── app.py                        # Flask backend (6 REST API endpoints)
│   ├── templates/
│   │   └── index.html                # Main HTML page
│   └── static/
│       ├── dashboard.js              # D3.js interactive visualizations
│       └── style.css                 # Dashboard styles
│
├── rules/                            # Detection rules
│   ├── yara/
│   │   └── big2015_rules.yar         # 8 YARA rules for malware families
│   └── snort/                        # Snort custom rules (optional)
│
├── data/                             # Datasets (not in git)
│   ├── malware_samples_bazaar/       # MalwareBazaar sample metadata (JSON)
│   ├── cape_reports/                 # CAPEv2 JSON analysis reports (100 files)
│   ├── pcap/                         # CAPEv2 sandbox PCAP files (100 files)
│   └── detection_system.db           # SQLite database
│
├── demo_runner.py                    # End-to-end demo script
├── requirements_pip.txt              # Python dependencies
├── requirements.txt                  # Project requirements (academic)
├── project_summary.md                # Project work summary
├── requirements_mapping.md           # Requirements completion mapping
└── README.md                         # This file
```

---

## Core Modules

### `src/config.py` — Global Configuration
Central configuration for all paths, analysis thresholds, and correlation weights. Edit this file to customize system behavior.

```python
from src.config import Config
cfg = Config()
print(cfg.DB_PATH)           # SQLite database path
print(cfg.YARA_RULES_DIR)    # YARA rules directory
print(cfg.CORRELATION_THRESHOLD)  # Correlation score threshold (default: 0.30)
```

### `src/plugin_framework.py` — Extensible Plugin Architecture
All analyzers inherit from `BaseAnalyzer`. To add a new analyzer:

```python
from src.plugin_framework import BaseAnalyzer, PluginRegistry

class MyCustomAnalyzer(BaseAnalyzer):
    def analyze(self, input_data):
        # Your analysis logic here
        return AnalysisResult(...)

    def get_iocs(self):
        return [...]

# Register the plugin
PluginRegistry.register("my_analyzer", MyCustomAnalyzer)
```

### `src/static_analyzer.py` — Static Feature Analysis
Extracts file hashes (MD5, SHA-256), Shannon entropy, **byte frequency distribution (BFD)** anomalies (chi-squared uniformity, null byte ratio, non-printable ratio), readable strings, and PE header information. BFD analysis references Saxe & Berlin 2015 and Raff et al. 2017.

```python
from src.static_analyzer import StaticAnalyzer
analyzer = StaticAnalyzer()
result = analyzer.analyze("path/to/sample.exe")
print(result.alerts)     # List of alerts
print(result.iocs)       # List of IoCs (hashes, IPs, domains)
```

### `src/snort_wrapper.py` — Snort IDS Wrapper
Runs Snort against PCAP files and parses alerts into structured dictionaries.

```python
from src.snort_wrapper import SnortAnalyzer
analyzer = SnortAnalyzer()
result = analyzer.analyze("path/to/traffic.pcap")
for alert in result.alerts:
    print(f"{alert['timestamp']} | {alert['alert_type']} | {alert['src_ip']} → {alert['dst_ip']}")
```

### `src/yara_wrapper.py` — YARA Rule Engine
Scans files against custom YARA rules for known malware signatures.

```python
from src.yara_wrapper import YaraAnalyzer
analyzer = YaraAnalyzer()
result = analyzer.analyze("path/to/sample.bin")
print(result.matched_rules)  # e.g., ["Simda_Backdoor", "Ramnit_Worm"]
```

### `src/dynamic_analyzer.py` — CAPEv2 Integration
Submits samples to CAPEv2 sandbox and parses behavioral reports.

```python
from src.dynamic_analyzer import CapeAnalyzer
analyzer = CapeAnalyzer(api_url="http://<CAPE_HOST>:8000")
task_id = analyzer.submit("path/to/malware.exe")
report = analyzer.get_report(task_id)
print(report.processes)       # Process tree
print(report.network_calls)   # DNS queries, HTTP requests
print(report.file_operations)  # Created/modified files
```

### `src/correlation_engine.py` — Cross-Source Correlation
Links alerts from different sources using 5-dimension weighted matching with multiplicative temporal boosting and threat-level modulation.

```python
from src.correlation_engine import CorrelationEngine
engine = CorrelationEngine()
engine.add_alerts(all_alerts)
correlations = engine.correlate()
for corr in correlations:
    print(f"Score: {corr.total_score:.2f} | {corr.source_1} ↔ {corr.source_2}")
```

### `src/database.py` — SQLite Persistence
Stores all alerts, samples, correlations, and IoCs. Four core tables: `alerts`, `samples`, `correlations`, `iocs`.

### `src/orchestrator.py` — Pipeline Orchestrator
Coordinates the entire analysis pipeline: file discovery → static analysis → YARA → dynamic analysis → correlation → database storage.

```python
from src.orchestrator import Orchestrator
orch = Orchestrator()

# Analyze a single file
orch.analyze_file("path/to/sample.exe")

# Analyze a directory of files
orch.analyze_directory("path/to/samples/")

# Full pipeline with PCAP
orch.run_full_pipeline(sample_dir="data/malware_samples/", pcap_dir="data/pcap/")
```

---

## Usage

### Quick Start

Run the full analysis pipeline on MalwareBazaar samples:

```bash
conda activate detection-system

# Download 100 PE samples from MalwareBazaar
python tools/download_malwarebazaar.py

# Run static + YARA analysis
python tools/run_bazaar_analysis.py

# Import CAPEv2 reports into database
python tools/import_cape_results.py

# Run Snort on sandbox PCAPs
python tools/run_snort_pcaps.py

# Run cross-source correlation
python tools/run_correlation.py

# Launch web dashboard
python -m dashboard.app
```

### Real Dataset Analysis (MalwareBazaar)

Analyze real-world malware from MalwareBazaar:

```bash
# Step 1: Download 100 PE samples from MalwareBazaar daily batch
python tools/download_malwarebazaar.py

# Step 2: Run static analysis + YARA on all samples
python tools/run_bazaar_analysis.py
```

### Dynamic Analysis (CAPEv2)

Submit samples to CAPEv2 sandbox and import results:

```bash
# Submit samples to CAPEv2 (via REST API)
# Then import reports and PCAP files into the database:
python tools/import_cape_results.py
```

### Network Traffic Analysis (Snort)

Analyze CAPEv2 sandbox PCAP files using Snort in WSL2:

```bash
# Run Snort on all CAPEv2 sandbox PCAPs
python tools/run_snort_pcaps.py
```

### Correlation Engine

Run the cross-source correlation engine:

```bash
# Run correlations with threat-level modulation
python tools/run_correlation.py
```

### Web Dashboard

Launch the interactive visualization dashboard:

```bash
conda activate detection-system
python dashboard/app.py
# → Open http://localhost:5000 in your browser
```

**Dashboard features:**
- **Stats Overview**: Total alerts, IoCs, correlations
- **Timeline**: Interactive D3.js timeline of alert events
- **Attack Graph**: Force-directed correlation network with Min Score slider filtering
- **Alert Table**: Sortable, filterable table of all detected alerts
- **IoC Panel**: Aggregated indicators of compromise
- **File Upload**: Drag-and-drop real-time file analysis

**API Endpoints:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/stats` | GET | System-wide statistics |
| `/api/alerts` | GET | All alerts with IoC details |
| `/api/correlations` | GET | Cross-source correlation results |
| `/api/iocs` | GET | Aggregated IoC list |
| `/api/timeline` | GET | Timeline data for D3.js visualization |
| `/api/analyze` | POST | Real-time file upload analysis |

---

## Testing

Run the full test suite:

```bash
conda activate detection-system
python -m pytest tests/ -v
```

Run with coverage:

```bash
python -m pytest tests/ -v --cov=src --cov-report=term-missing
```

| Test File | Count | Description |
|-----------|------:|-------------|
| `test_utils.py` | 27 | Hash, entropy, string extraction, path safety |
| `test_plugin_framework.py` | 18 | BaseAnalyzer interface, PluginRegistry |
| `test_static_analyzer.py` | 19 | PE analysis, alert generation |
| `test_database.py` | 22 | CRUD operations, batch insert, queries |
| `test_correlation_engine.py` | 18 | 5D matching, threshold filtering, scoring |
| `test_orchestrator.py` | 18 | Pipeline orchestration, module coordination |
| **Total** | **122** | **All passing ✅** |

---

## Datasets

### MalwareBazaar (Primary Dataset)
- **Source**: abuse.ch MalwareBazaar Daily Batch (https://datalake.abuse.ch/malware-bazaar/daily/)
- **Size**: 100 PE executable samples (1KB-10MB each)
- **Selection**: Filtered from daily batch by MZ/PE header validation
- **Analysis Pipeline**: Static → YARA → CAPEv2 Dynamic → Snort PCAP → Correlation

---

## Tools & Utilities

| Script | Purpose |
|--------|---------|
| `tools/download_malwarebazaar.py` | Download PE samples from MalwareBazaar daily batch |
| `tools/run_bazaar_analysis.py` | Run static + YARA analysis on MalwareBazaar samples |
| `tools/import_cape_results.py` | Download and import CAPEv2 reports + PCAPs |
| `tools/run_snort_pcaps.py` | Run Snort on CAPEv2 sandbox PCAPs via WSL |
| `tools/run_correlation.py` | Cross-source correlation engine (v8 threat modulation) |
| `tools/evaluate.py` | Run comprehensive performance evaluation |
| `tools/integrate_snort_alerts.py` | Parse and import Snort alerts into SQLite |
| `tools/setup_wsl_snort.sh` | Automated WSL2 + Snort installation |

---

## Configuration

Edit `src/config.py` to customize:

```python
# Analysis thresholds
ENTROPY_THRESHOLD = 7.0          # High entropy → possible packing/encryption
CORRELATION_THRESHOLD = 0.30     # Minimum score to create a correlation

# Correlation weights — 5D (must sum to 1.0)
WEIGHT_IP = 0.25                 # Network-layer indicator
WEIGHT_DOMAIN = 0.25             # Domain/URL match
WEIGHT_HASH = 0.30               # File-layer indicator (capped to single hit)
WEIGHT_BEHAVIOR = 0.20           # Behavior/TTP similarity

# Time is a multiplicative booster, NOT an additive dimension
TIME_BOOST = 1.3                 # Score × 1.3 when within time window
TIME_WINDOW = 300                # 5 minutes

# CAPEv2 settings
CAPE_API_URL = "http://<CAPE_HOST>:8000"
CAPE_TIMEOUT = 300               # Analysis timeout in seconds
```

---

## Evaluation

Run the full evaluation:

```bash
python tools/evaluate.py
```

**Key Results (MalwareBazaar Dataset):**

| Metric | Value |
|--------|-------|
| Samples Analyzed | 100 PE executables |
| Static Analysis Alerts | 146 |
| YARA Detections | 33 |
| CAPEv2 Dynamic Alerts | 322 |
| Total Alerts | **501** |
| Total IoCs Extracted | **27,684** |
| Cross-Source Correlations | **506** (scores 0.34–0.50) |
| Correlation Score Levels | 5 (threat-level modulated) |

---

## License

This project was developed as part of a BSc (Hons) Cyber Security dissertation. For academic use only.
