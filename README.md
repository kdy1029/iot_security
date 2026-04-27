# Assessing IoT Android App Security

This repository contains the data analysis scripts and visualization code for the research paper:

> **Assessing IoT Android App Security: Static Components, Privacy Threats and Vulnerabilities.**  
> Firdous Samreen, Sawsan Imleh, Daeyoung Kim.  
> *In the 12th EAI International Conference on Mobility, IoT and Smart Cities, December 2025.*

## Overview

This project provides a suite of Python scripts to automate the security assessment of Android applications, with a particular focus on Internet of Things (IoT) apps. The workflow includes:
1.  Fetching application metadata from the Google Play Store.
2.  Importing and parsing static analysis reports from **MobSF** and **Drozer**.
3.  Storing the structured data in a PostgreSQL database.
4.  Querying the database to perform analysis.
5.  Generating tables (LaTeX) and figures (PDF, PNG) that highlight key security and privacy metrics.

## Project Structure

-   `list.csv`: Input file containing the package names of Android apps to be analyzed.
-   `results/`: Directory to store raw JSON output files from MobSF static analysis.
-   `dz_out_*/`: Directories containing raw log files from Drozer scans.
-   `*.py`: Python scripts for data processing, database interaction, and analysis.
-   `outputs/`: Generated CSV files and summaries from `parse_drozer_logs.py`.
-   `tables/`: Generated LaTeX tables summarizing the analysis results.
-   `figures/`: Generated plots and graphs visualizing the findings.

## Setup

### 1. Dependencies

This project requires Python 3 and a running PostgreSQL instance. You can install the necessary Python libraries using pip:

```bash
pip install pandas sqlalchemy psycopg2-binary matplotlib google-play-scraper tabulate python-slugify
```

It is recommended to create a `requirements.txt` file for better dependency management.

### 2. Database Configuration

The scripts connect to a PostgreSQL database. The connection string is retrieved from the `PG_DSN` environment variable. You should set it before running the scripts.

**Example:**
```bash
# On Linux/macOS
export PG_DSN="dbname=iot_security user=postgres password=your_password host=localhost"

# On Windows (Command Prompt)
set PG_DSN="dbname=iot_security user=postgres password=your_password host=localhost"
```

The project assumes a database schema with tables like `play_apps` and `app_analysis`, along with several views (`v_risk_score`, `v_masvs_mapping`, etc.) to facilitate querying. You will need to create these tables and views based on the analysis goals before running the scripts.

## Workflow

1.  **Prepare Inputs**:
    -   Populate `list.csv` with the Android package names you want to analyze, one per line.
    -   Place the JSON reports from your MobSF scans into the `results/` directory.
    -   Place the output directories from your Drozer scans (e.g., `dz_out_com.example.app`) into the project root.

2.  **Fetch App Metadata**:
    Run `extract_desc.py` to fetch details from the Google Play Store and populate the `play_apps` table in your database.
    ```bash
    python extract_desc.py
    ```

3.  **Import Analysis Data**:
    -   Run `import_json_to_db.py` to parse and import the MobSF JSON reports into the `app_analysis` table.
        ```bash
        python import_json_to_db.py
        ```
    -   Run `parse_drozer_logs.py` to parse Drozer logs and save the summary to the `outputs/` directory.
        ```bash
        python parse_drozer_logs.py --root "dz_out_*"
        ```

4.  **Generate Results**:
    Run the analysis scripts to generate the final tables and figures from the data stored in the database.
    ```bash
    python generate_graphs.py
    python generate_tables.py
    python generate_masvs_plots.py
    ```
    The final artifacts will be saved in the `tables/` and `figures/` directories.
