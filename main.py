from datetime import datetime
from pathlib import Path
import sys
from typing import Optional

# Import custom modules
from src import download_files, s3_upload, yara_scan

def main(date_str: str) -> None:
    """
    Main function to process files from VX Underground.

    Args:
        date_str (str): The date in 'YYYY-MM-DD' format.
    """
    # Convert the date string to a datetime object
    date: datetime = datetime.strptime(date_str, "%Y-%m-%d")
    # Download the archive for the specified date
    zip_path: Optional[Path] = download_files.download_file(date)
    if zip_path:
        # Extract files from the downloaded archive
        extracted_dir: Path = download_files.extract_files(zip_path)
        # Path to the YARA rules directory
        rules_dir: Path = Path('yara_rules')
        # Output file for scan results
        output_file: Path = Path('scan_results') / f"scan_results_{date.strftime('%Y_%m_%d')}.json"
        output_file.parent.mkdir(exist_ok=True)

        # Scan the extracted files with YARA rules
        scan_results = yara_scan.scan_files(extracted_dir, rules_dir)
        # Save the scan results to a JSON file
        yara_scan.save_results(scan_results, output_file)

        # Determine the key prefix based on the archive name
        key_prefix: str = zip_path.stem  # Name of the archive without extension

        # Upload the extracted files to S3 under the key prefix
        s3_upload.upload_to_s3(extracted_dir, "my-bucket", key_prefix=key_prefix)

        # Upload the scan results to S3 under the key prefix
        s3_upload.upload_to_s3(output_file, "my-bucket", key_prefix=key_prefix)

        # Optional: Clean up local files after processing
        import shutil
        # Remove the extracted files directory
        shutil.rmtree(extracted_dir)
        # Remove the downloaded archive
        zip_path.unlink()
        # Remove the scan results file
        output_file.unlink()
    else:
        print("Download failed.")

if __name__ == "__main__":
    # Check if a date argument was provided
    if len(sys.argv) != 2:
        print("Usage: python main.py YYYY-MM-DD")
    else:
        # Run the main function with the provided date
        main(sys.argv[1])
