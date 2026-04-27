#!/usr/bin/env python3
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.data_ingestion import fetch_play_metadata

def main():
    pkgs_file = sys.argv[1] if len(sys.argv) > 1 else "list.csv"
    fetch_play_metadata(pkgs_file)

if __name__ == "__main__":
    main()
