import boto3
from pathlib import Path

def upload_to_s3(path: Path, bucket_name: str):
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

    if path.is_dir():
        # Рекурсивно загружаем все файлы из директории
        for file_path in path.rglob("*"):
            if file_path.is_file():
                # Определяем относительный путь относительно `path`, если возможно
                try:
                    s3_path = str(file_path.relative_to(path))
                except ValueError:
                    s3_path = file_path.name  # Если не получается, используем только имя файла

                s3.upload_file(str(file_path), bucket_name, s3_path)
                print(f"Загружен {file_path} в S3 {bucket_name}/{s3_path}")
    elif path.is_file():
        # Загружаем один файл, если путь является файлом
        s3_path = path.name
        s3.upload_file(str(path), bucket_name, s3_path)
        print(f"Загружен {path} в S3 {bucket_name}/{s3_path}")
    else:
        print(f"Путь {path} не является файлом или директорией.")
