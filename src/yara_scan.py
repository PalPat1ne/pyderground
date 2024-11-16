# yara_scan.py

import yara
from pathlib import Path
import json
from typing import Dict, List

def scan_files(directory: Path, rules_dir: Path) -> Dict[str, List[str]]:
    """
    Scans files in a given directory using YARA rules from a specified rules directory.

    Args:
        directory (Path): The directory containing files to scan.
        rules_dir (Path): The directory containing YARA rule files (*.yar).

    Returns:
        Dict[str, List[str]]: A dictionary mapping file names to a list of matched YARA rule names.
    """
    # Compile all YARA rules from the rules directory
    rule_files = [str(p) for p in rules_dir.glob("*.yar")]
    if not rule_files:
        raise ValueError(f"No YARA rule files found in {rules_dir}")
    rules = yara.compile(filepaths={f"rule_{i}": rf for i, rf in enumerate(rule_files)})

    scan_results: Dict[str, List[str]] = {}

    # Recursively scan all files in the directory
    for file_path in directory.rglob("*"):
        if file_path.is_file():
            try:
                # Match the file against the compiled YARA rules
                matches = rules.match(filepath=str(file_path))
                if matches:
                    # Store the matched rule names
                    scan_results[file_path.name] = [match.rule for match in matches]
            except yara.Error as e:
                print(f"Error scanning {file_path}: {e}")

    return scan_results

def save_results(results: Dict[str, List[str]], output_file: Path) -> None:
    """
    Saves the scanning results to a JSON file.

    Args:
        results (Dict[str, List[str]]): The scanning results to save.
        output_file (Path): The output JSON file path.
    """
    with output_file.open("w") as f:
        json.dump(results, f, indent=4)
        print(f"Results saved to {output_file}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Scan files using YARA rules.")
    parser.add_argument("directory", type=Path, help="Directory containing files to scan")
    parser.add_argument("rules_dir", type=Path, help="Directory containing YARA rule files (*.yar)")
    parser.add_argument("output_file", type=Path, help="Output file to save the results (JSON)")

    args = parser.parse_args()

    results = scan_files(args.directory, args.rules_dir)
    save_results(results, args.output_file)
