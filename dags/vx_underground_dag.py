from datetime import datetime, timedelta
from airflow import DAG
from airflow.operators.python_operator import PythonOperator
from pathlib import Path
from typing import Optional
import sys
import os
sys.path.append('/opt/airflow/app')

# Import custom modules
from src import download_files, s3_upload, yara_scan

def vx_underground_processing(**kwargs) -> None:
    """
    Airflow task function to process VX Underground files.
    """
    # Get the execution date from Airflow context
    date_str: str = kwargs.get('dag_run').conf.get('date')
    if not date_str:
        # Если дата не указана, используем текущую дату
        date_str = kwargs['ds']
    # Convert the date string to a datetime object
    date: datetime = datetime.strptime(date_str, "%Y-%m-%d")
    # Download the archive for the specified date
    zip_path: Optional[Path] = download_files.download_file(date)
    if zip_path:
        # Extract files from the downloaded archive
        extracted_dir: Path = download_files.extract_files(zip_path)
        # Path to the YARA rules directory in Airflow
        rules_dir: Path = Path('yara_rules')  # Adjust path as needed
        # Output file for scan results
        output_file: Path = Path('scan_results') / f"scan_results_{date.strftime('%Y_%m_%d')}.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Scan the extracted files with YARA rules
        scan_results = yara_scan.scan_files(extracted_dir, rules_dir)
        # Save the scan results to a JSON file
        yara_scan.save_results(scan_results, output_file)

        # Upload the extracted files and scan results to S3
        s3_upload.upload_to_s3(extracted_dir, "my-bucket")
        s3_upload.upload_to_s3(output_file, "my-bucket")
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
