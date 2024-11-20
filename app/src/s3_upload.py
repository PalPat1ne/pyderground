import boto3
from botocore.exceptions import BotoCoreError, ClientError
from pathlib import Path
from typing import Optional

def upload_to_s3(path: Path, bucket_name: str, key_prefix: str = "") -> None:
    """
    Upload files or directories to an S3 bucket.

    Args:
        path (Path): The file or directory to upload.
        bucket_name (str): The name of the S3 bucket.
        key_prefix (str): The prefix (folder) in the S3 bucket.
    """
    # Initialize the S3 client (adjust endpoint_url if necessary)
    s3 = boto3.client(
        's3',
        endpoint_url="http://localhost:9000",  # For MinIO, adjust as needed
        aws_access_key_id="minioadmin",
        aws_secret_access_key="minioadmin",
    )

    # Check if the bucket exists; create it if it doesn't
    try:
        s3.head_bucket(Bucket=bucket_name)
    except ClientError:
        try:
            s3.create_bucket(Bucket=bucket_name)
            print(f"Bucket '{bucket_name}' created.")
        except (BotoCoreError, ClientError) as e:
            print(f"Error creating bucket '{bucket_name}': {e}")
            return

    # Function to check if prefix exists
    def prefix_exists(s3_client, bucket_name: str, prefix: str) -> bool:
        response = s3_client.list_objects_v2(Bucket=bucket_name, Prefix=prefix, MaxKeys=1)
        return 'Contents' in response

    # Check if the prefix already exists
    if key_prefix and prefix_exists(s3, bucket_name, key_prefix):
        print(f"Prefix '{key_prefix}' already exists in bucket '{bucket_name}'.")
        # Decide how to handle this situation: skip, overwrite, or raise an error
        # For this example, we'll proceed and overwrite

    if path.is_dir():
        # Upload all files in the directory recursively
        for file_path in path.rglob("*"):
            if file_path.is_file():
                # Calculate the S3 object name relative to the upload path
                try:
                    relative_path = file_path.relative_to(path)
                    s3_path: str = f"{key_prefix}/{str(relative_path)}"
                except ValueError:
                    s3_path = f"{key_prefix}/{file_path.name}"  # Use the file name if relative path can't be determined
                # Upload the file to S3
                try:
                    s3.upload_file(str(file_path), bucket_name, s3_path)
                    print(f"Uploaded {file_path} to S3 bucket {bucket_name} as {s3_path}")
                except (BotoCoreError, ClientError) as e:
                    print(f"Error uploading {file_path} to S3: {e}")
    elif path.is_file():
        # Upload a single file
        s3_path: str = f"{key_prefix}/{path.name}"
        try:
            s3.upload_file(str(path), bucket_name, s3_path)
            print(f"Uploaded {path} to S3 bucket {bucket_name} as {s3_path}")
        except (BotoCoreError, ClientError) as e:
            print(f"Error uploading {path} to S3: {e}")
    else:
        print(f"The path {path} is neither a file nor a directory.")
