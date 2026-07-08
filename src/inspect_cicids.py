"""
Project Darkroom - Week 1
Step 1: Extract and inspect the CIC-IDS2017 dataset structure before building
conversion logic. We inspect first because different redistributed copies of
this dataset have slightly different columns (some include IPs/ports, some don't).

Source: Kaggle mirror of the CIC-IDS2017 dataset (dhoogla/cicids2017),
        originally from the Canadian Institute for Cybersecurity (CIC), UNB
        https://www.unb.ca/cic/datasets/ids-2017.html
License: Free for academic, research, and commercial use under the CIC dataset license.

Note: The zip must already be downloaded manually from Kaggle and placed at
      data/raw/CIC-IDS2017/cicids2017.zip before running this script.
"""

import zipfile
from pathlib import Path

RAW_DIR = Path("data/raw/CIC-IDS2017")
ZIP_PATH = RAW_DIR / "cicids2017.zip"


def extract_zip():
    extract_dir = RAW_DIR / "extracted"
    if extract_dir.exists() and any(extract_dir.iterdir()):
        print(f"Already extracted at {extract_dir}, skipping.")
        return extract_dir

    if not ZIP_PATH.exists():
        raise FileNotFoundError(
            f"Expected zip at {ZIP_PATH} - download it from Kaggle first "
            f"and place it there."
        )

    print("Extracting...")
    with zipfile.ZipFile(ZIP_PATH, "r") as z:
        z.extractall(extract_dir)
    print(f"Extracted to {extract_dir}")
    return extract_dir


def inspect_files(extract_dir):
    all_files = list(extract_dir.rglob("*"))
    file_only = [f for f in all_files if f.is_file()]

    print(f"\nFound {len(file_only)} files total. Extensions present:")
    extensions = {}
    for f in file_only:
        ext = f.suffix.lower()
        extensions[ext] = extensions.get(ext, 0) + 1
    for ext, count in extensions.items():
        print(f"  {ext or '(no extension)'}: {count} file(s)")

    print("\nFull file listing:")
    for f in file_only:
        size_mb = f.stat().st_size / 1_000_000
        print(f"  {f.relative_to(extract_dir)}  ({size_mb:.1f} MB)")

    csv_files = [f for f in file_only if f.suffix.lower() == ".csv"]
    parquet_files = [f for f in file_only if f.suffix.lower() == ".parquet"]

    import pandas as pd

    if parquet_files:
        sample_file = parquet_files[0]
        print(f"\nInspecting columns of (parquet): {sample_file.name}")
        df = pd.read_parquet(sample_file)
        print(f"\nColumns ({len(df.columns)} total):")
        for col in df.columns:
            print(f"  {col}")
        print(f"\nTotal rows: {len(df)}")
        print("\nSample rows:")
        print(df.head(3).to_string())
    elif csv_files:
        sample_file = csv_files[0]
        print(f"\nInspecting columns of (csv): {sample_file.name}")
        df = pd.read_csv(sample_file, nrows=5)
        print(f"\nColumns ({len(df.columns)} total):")
        for col in df.columns:
            print(f"  {col}")
        print("\nSample rows:")
        print(df.head(3).to_string())
    else:
        print("\nNo CSV or Parquet files found - unrecognized format, check listing above.")


if __name__ == "__main__":
    extract_dir = extract_zip()
    inspect_files(extract_dir)