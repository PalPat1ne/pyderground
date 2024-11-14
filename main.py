# main.py

from datetime import datetime
from pathlib import Path
from src import download_files, s3_upload, yara_scan

def main(date_str: str):
    date = datetime.strptime(date_str, "%Y-%m-%d")
    zip_path = download_files.download_file(date)
    if zip_path:
        extracted_dir = download_files.extract_files(zip_path)
        rules_dir = Path('yara_rules')
        scan_results = yara_scan.scan_files(extracted_dir, rules_dir)
        yara_scan.save_results(scan_results, Path('scan_results.json'))
        s3_upload.upload_to_s3(extracted_dir, "my-bucket")
        s3_upload.upload_to_s3(Path("scan_results.json"), "my-bucket")
    else:
        print("Скачивание файла не удалось.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Использование: python main.py YYYY-MM-DD")
    else:
        main(sys.argv[1])
