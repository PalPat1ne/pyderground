# yara_scan.py

import yara
from pathlib import Path
import json

def scan_files(directory: Path, rules_dir: Path) -> dict:
    # Компилируем все правила из директории
    rule_files = [str(p) for p in rules_dir.glob("*.yar")]
    rules = yara.compile(filepaths={f"rule_{i}": rf for i, rf in enumerate(rule_files)})
    scan_results = {}

    for file_path in directory.glob("**/*"):
        if file_path.is_file():
            matches = rules.match(filepath=str(file_path))
            scan_results[file_path.name] = [match.rule for match in matches]

    return scan_results

def save_results(results: dict, output_file: Path):
    with open(output_file, "w") as f:
        json.dump(results, f, indent=4)
