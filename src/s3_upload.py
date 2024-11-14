import boto3
from pathlib import Path

def upload_to_s3(directory: Path, bucket_name: str):
    s3 = boto3.client(
        's3',
        endpoint_url="http://localhost:9000",  # Для MinIO
        aws_access_key_id="minioadmin",
        aws_secret_access_key="minioadmin",
    )
    # Создаём bucket, если его нет
    try:
        s3.create_bucket(Bucket=bucket_name)
    except s3.exceptions.BucketAlreadyOwnedByYou:
        pass

    for file in directory.glob("**/*"):
        if file.is_file():
            s3.upload_file(str(file), bucket_name, file.name)
            print(f"Загружен файл: {file.name}")
