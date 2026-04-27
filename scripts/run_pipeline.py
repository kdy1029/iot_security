#!/usr/bin/env python3
import sys
import os

# Add parent directory to sys.path to allow importing from src
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.data_ingestion import import_mobsf_json_to_db, parse_drozer_logs
from src.visualization import generate_all_visualizations

def main():
    print("=== IoT App Security Analysis Pipeline ===")
    
    # 1. Check Database connection
    print("\n--- Phase 1: Database Setup ---")
    try:
        from src.database import get_connection
        with get_connection() as conn:
            print("[OK] Database connection successful.")
    except Exception as e:
        print(f"[FAIL] Database connection failed: {e}")
        print("Please set the PG_DSN environment variable correctly.")
        sys.exit(1)

    # 2. Import Data (MobSF + Drozer)
    print("\n--- Phase 2: Data Ingestion ---")
    
    data_dir = "results"
    if not os.path.exists(data_dir):
        print(f"[WARNING] Directory '{data_dir}' not found. Skipping MobSF JSON import.")
    else:
        import_mobsf_json_to_db(data_dir)

    print("\nParsing Drozer Logs...")
    parse_drozer_logs("dz_out_*", "outputs")

    # 3. Generate Visualizations and Tables
    print("\n--- Phase 3: Generating Outputs ---")
    generate_all_visualizations()
    
    print("\n=== Pipeline Completed ===")

if __name__ == "__main__":
    main()
