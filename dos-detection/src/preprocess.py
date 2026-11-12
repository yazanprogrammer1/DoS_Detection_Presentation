"""
preprocess.py - Clean CIC-IDS2017 CSV files and save them as Parquet.

Usage (from the dos-detection folder):
    python src/preprocess.py
"""
from pathlib import Path

import numpy as np
import pandas as pd

# ---------- Paths ----------
ROOT = Path(__file__).resolve().parents[1]      # dos-detection/
RAW_DIR = ROOT / "data" / "raw"
OUT_DIR = ROOT / "data" / "processed"

FILES = {
    "wednesday": "Wednesday-workingHours.pcap_ISCX.csv",
    "friday": "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
}

# ---------- Decisions taken during EDA ----------
CONSTANT_COLS = [
    "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "CWE Flag Count",
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
]
DROP_COLS = ["Destination Port", "Fwd Header Length.1"] + CONSTANT_COLS
EXCLUDED_LABELS = ["Heartbleed"]


def clean(df: pd.DataFrame, name: str):
    """Apply the same cleaning steps to any CIC-IDS2017 file."""
    report = {"file": name, "rows_raw": len(df)}

    # 1) Remove spaces around column names
    df.columns = df.columns.str.strip()

    # 2) Remove labels that are not DoS attacks
    df = df[~df["Label"].isin(EXCLUDED_LABELS)]

    # 3) Drop useless / misleading columns
    df = df.drop(columns=DROP_COLS)

    # 4) inf comes from division by zero -> treat as missing, then drop
    df = df.replace([np.inf, -np.inf], np.nan)
    report["rows_nan_inf"] = int(df.isna().any(axis=1).sum())
    df = df.dropna()

    # 5) Remove exact duplicates (prevents train/test leakage)
    report["rows_duplicated"] = int(df.duplicated().sum())
    df = df.drop_duplicates()

    # 6) Binary target: 0 = benign, 1 = attack (keep Label for analysis)
    df["is_attack"] = (df["Label"] != "BENIGN").astype("int8")

    report["rows_clean"] = len(df)
    report["n_features"] = df.shape[1] - 2      # minus Label and is_attack
    return df.reset_index(drop=True), report


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    reports = []

    for name, filename in FILES.items():
        print(f"Reading {filename} ...")
        df = pd.read_csv(RAW_DIR / filename)
        df, report = clean(df, name)

        df.to_parquet(OUT_DIR / f"{name}_clean.parquet", index=False)
        reports.append(report)
        print(df["Label"].value_counts(), "\n")

    summary = pd.DataFrame(reports)
    print(summary.to_string(index=False))
    summary.to_csv(ROOT / "results" / "cleaning_report.csv", index=False)


if __name__ == "__main__":
    main()
