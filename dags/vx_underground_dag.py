from datetime import datetime, timedelta
from airflow import DAG
from airflow.operators.python_operator import PythonOperator
from pathlib import Path
from typing import Optional
import sys
import os
import shutil
sys.path.append('/opt/airflow/app')

# Import custom modules
from src import download_files, s3_upload, yara_scan

def vx_underground_processing(**kwargs) -> None:
    """
    Airflow task function to process VX Underground files.
    """
    # Get the execution date from Airflow context
    date_str: str = kwargs['ds']
    date: datetime = datetime.strptime(date_str, "%Y-%m-%d")

    # Download the archive
    zip_path = download_files.download_file(date)
    if zip_path:
        # Extract files from the archive
        extracted_dir = download_files.extract_files(zip_path)

        # Define S3 bucket and key prefixes
        bucket_name: str = "my-bucket"
        viruses_key_prefix: str = f"viruses/{date.strftime('%Y.%m.%d')}"  # Separate folder for extracted files

        # Path to the YARA rules and scan results
        rules_dir = Path('/opt/airflow/app/yara_rules')
        results_file = Path('/opt/airflow/app/scan_results') / f"scan_results_{date.strftime('%Y_%m_%d')}.json"
        results_file.parent.mkdir(parents=True, exist_ok=True)

        # Scan the files and save results
        scan_results = yara_scan.scan_files(extracted_dir, rules_dir)
        yara_scan.save_results(scan_results, results_file)

        # Upload extracted files (viruses) to their date-specific folder
        s3_upload.upload_to_s3(extracted_dir, bucket_name, key_prefix=viruses_key_prefix)

        # Upload scan results to the common results folder
        s3_upload.upload_to_s3(results_file, bucket_name, is_results=True)

        # Clean up local files
        shutil.rmtree(extracted_dir)  # Remove the extracted files directory
        zip_path.unlink()  # Remove the downloaded archive
        results_file.unlink()  # Remove the results file
    else:
        print("Download failed.")


# Default arguments for the DAG
default_args = {
    'owner': 'airflow',
    'start_date': datetime(2023, 1, 1),
    'retries': 1,
    'retry_delay': timedelta(minutes=5),
}

# Define the DAG
with DAG(
    'vx_underground_processing',
    default_args=default_args,
    schedule_interval='0 0 * * *',  # Runs daily at midnight
    catchup=False,
) as dag:
    # Define the Python task
    task = PythonOperator(
        task_id='vx_processing_task',
        python_callable=vx_underground_processing,
        provide_context=True,
    )
