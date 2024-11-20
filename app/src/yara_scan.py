# yara_scan.py

import yara
from pathlib import Path
import json
from typing import Dict, List

def scan_files(directory: Path, rules_dir: Path) -> Dict[str, List[str]]:
    """
    Scan files in a given directory using YARA rules from the specified rules directory.

    Args:
        directory (Path): The directory containing files to scan.
        rules_dir (Path): The directory containing YARA rule files (*.yar).

    Returns:
        Dict[str, List[str]]: A dictionary mapping file names to a list of matched YARA rule names.
    """
    # Collect all YARA rule files in the rules directory
    rule_files: List[str] = [str(p) for p in rules_dir.glob("*.yar")]
    if not rule_files:
        raise ValueError(f"No YARA rule files found in {rules_dir}")
    # Compile all YARA rules
    rules = yara.compile(filepaths={f"rule_{i}": rf for i, rf in enumerate(rule_files)})

    # Dictionary to store scan results
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
    Save the scanning results to a JSON file.

    Args:
        results (Dict[str, List[str]]): The scanning results to save.
        output_file (Path): The output JSON file path.
    """
    # Write the results dictionary to a JSON file
    with output_file.open("w") as f:
        json.dump(results, f, indent=4)
    print(f"Results saved to {output_file}")
