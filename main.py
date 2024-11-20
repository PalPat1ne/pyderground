from datetime import datetime
from pathlib import Path
import sys
from typing import Optional
import shutil

# Import custom modules
from src import download_files, s3_upload, yara_scan

def main(date_str: str) -> None:
    """
    Main function to process files from VX Underground.

    Args:
        date_str (str): The date in 'YYYY-MM-DD' format.
    """
    try:
        # Convert the date string to a datetime object
        date: datetime = datetime.strptime(date_str, "%Y-%m-%d")

        # Download the archive for the specified date
        zip_path: Optional[Path] = download_files.download_file(date)
        if not zip_path:
            print("Download failed. Exiting.")
            return

        # Extract files from the downloaded archive
        extracted_dir: Path = download_files.extract_files(zip_path)

        # Define paths for YARA rules and scan results
        rules_dir: Path = Path('yara_rules')  # Directory containing YARA rules
        output_file: Path = Path('scan_results') / f"scan_results_{date.strftime('%Y_%m_%d')}.json"
        output_file.parent.mkdir(exist_ok=True)

        # Scan the extracted files with YARA rules
        scan_results = yara_scan.scan_files(extracted_dir, rules_dir)
        # Save the scan results to a JSON file
        yara_scan.save_results(scan_results, output_file)

        # Define S3 key prefixes
        viruses_key_prefix: str = f"viruses/{date.strftime('%Y.%m.%d')}"  # Folder for extracted files
        results_key_prefix: str = "results"  # Common folder for scan results

        # Upload the extracted files to S3 under the date-specific key prefix
        s3_upload.upload_to_s3(extracted_dir, "my-bucket", key_prefix=viruses_key_prefix)

        # Upload the scan results to the common results folder
        s3_upload.upload_to_s3(output_file, "my-bucket", is_results=True)

        # Clean up local files after processing
        print("Cleaning up local files...")
        shutil.rmtree(extracted_dir, ignore_errors=True)  # Remove the extracted files directory
        zip_path.unlink(missing_ok=True)  # Remove the downloaded archive
        output_file.unlink(missing_ok=True)  # Remove the scan results file

        print("Processing completed successfully.")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    # Check if a date argument was provided
    if len(sys.argv) != 2:
        print("Usage: python main.py YYYY-MM-DD")
    else:
        # Run the main function with the provided date
        main(sys.argv[1])
