# Assessing IoT Android App Security

This repository contains the data analysis scripts and visualization code for the research paper:

> **Assessing IoT Android App Security: Static Components, Privacy Threats and Vulnerabilities.**  
> Firdous Samreen, Sawsan Imleh, Daeyoung Kim.  
> *In the 12th EAI International Conference on Mobility, IoT and Smart Cities, December 2025.*

## Overview

This project provides a suite of Python scripts to automate the security assessment of Android applications, with a particular focus on Internet of Things (IoT) apps. The workflow includes:
1. Fetching application metadata from the Google Play Store.
2. Importing and parsing static analysis reports from **MobSF** and **Drozer**.
3. Storing the structured data in a PostgreSQL database.
4. Querying the database to perform risk scoring and security analysis.
5. Generating tables (LaTeX) and figures (PDF, PNG) that highlight key security and privacy metrics.

## Project Structure

```text
iot_security/
├── src/                     # Core application logic
│   ├── database.py          # Database connection management
│   ├── data_ingestion.py    # Importing JSON and logs into PostgreSQL
│   ├── analysis.py          # SQL logic and pandas dataframe processing
│   └── visualization.py     # Generating LaTeX tables and matplotlib figures
├── scripts/                 # Executable scripts
│   ├── run_pipeline.py      # Main entry point to run the analysis pipeline
│   └── fetch_metadata.py    # Google Play Store metadata fetcher
├── results/                 # Raw JSON output files from MobSF static analysis
├── dz_out_*/                # Raw log directories from Drozer scans (not committed)
├── tables/                  # Generated LaTeX tables
├── figures/                 # Generated plots and graphs
├── outputs/                 # Drozer parsed outputs
├── list.csv                 # Input file containing the package names of Android apps
├── requirements.txt         # Python dependencies
└── README.md
```

## Setup

### 1. Requirements

This project requires Python 3.8+ and a running PostgreSQL instance. Install the dependencies using pip:

```bash
pip install -r requirements.txt
```

### 2. Database Configuration

The application requires a PostgreSQL database. The connection string is retrieved from the `PG_DSN` environment variable. **Do not hardcode credentials in the scripts.**

1.  Create a PostgreSQL database and user:
    ```sql
    CREATE DATABASE iot_security;
    CREATE USER postgres WITH PASSWORD 'your_secure_password';
    GRANT ALL PRIVILEGES ON DATABASE iot_security TO postgres;
    ```
2.  Set the `PG_DSN` environment variable:

    **Linux / macOS:**
    ```bash
    export PG_DSN="postgresql://postgres:your_secure_password@localhost:5432/iot_security"
    ```

    **Windows (PowerShell):**
    ```powershell
    $env:PG_DSN="postgresql://postgres:your_secure_password@localhost:5432/iot_security"
    ```

3.  *Note:* The project assumes you have pre-configured tables (`play_apps`, `app_analysis`) and views (`v_risk_score`, `v_masvs_mapping`, `v_mobsf_permissions`, etc.) according to your analysis schema.

## Workflow

### 1. Prepare Inputs
1. Populate `list.csv` with the Android package names you want to analyze, one per line.
2. Place the JSON reports from your MobSF scans into the `results/` directory.
3. Place the output directories from your Drozer scans (e.g., `dz_out_com.example.app`) into the root directory.

### 2. Fetch App Metadata (Optional)
If you need fresh metadata from the Google Play Store, you can run the ingestion script:
```bash
python scripts/fetch_metadata.py list.csv
```

### 3. Run Analysis Pipeline
The `run_pipeline.py` script automates the process of connecting to the database, importing MobSF JSON results, parsing Drozer logs, and generating all visualizations and tables.

```bash
python scripts/run_pipeline.py
```

## Generated Outputs

After running the pipeline, the following artifacts are generated:
- **`tables/`**: LaTeX tables for Top Dangerous Permissions, Insecure Flags, and Credential Findings.
- **`figures/`**: PDF and PNG graphs for Top Domains, Risk Score Histograms, and MASVS Violations.
- **`outputs/`**: CSV summaries and extracted URIs from the Drozer log parser.
