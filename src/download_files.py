import requests
from pathlib import Path
from datetime import datetime
from typing import Optional
import py7zr  # Library for working with 7z archives
from tqdm import tqdm  # For progress bar
import os
def download_file(date: datetime) -> Optional[Path]:
    """
    Download the archive file for the given date from VX Underground.

    Args:
        date (datetime): The date for which to download the file.

    Returns:
        Optional[Path]: The path to the downloaded file, or None if the download failed.
    """
    # Base URL for VX Underground samples
    base_url: str = "https://samples.vx-underground.org/Samples/VirusSign%20Collection/"
    # Folder in format 'YYYY.MM'
    folder: str = date.strftime('%Y.%m')

    # Determine the filename based on the date
    if date < datetime(2024, 2, 1):
        # For dates before February 2024, use 'VirusSign' with capital 'S'
        filename: str = f"VirusSign.{date.strftime('%Y.%m.%d')}.7z"
    else:
        # For dates from February 2024 onwards, use 'Virussign' with lowercase 's'
        filename: str = f"Virussign.{date.strftime('%Y.%m.%d')}.7z"

    # Full URL to the archive
    url: str = f"{base_url}{folder}/{filename}"

    # Path to save the downloaded file
    zip_path: Path = Path("downloads") / filename
    # Create the downloads directory if it doesn't exist
    zip_path.parent.mkdir(exist_ok=True)

    # Check if the file has already been downloaded
    if zip_path.exists():
        print(f"Файл {filename} уже загружен ранее.")
        return zip_path

    # Attempt to download the file
    try:
        response: requests.Response = requests.get(url, stream=True)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Ошибка при скачивании файла: {e}")
        return None

    if response.status_code == 200:
        # Get the total file size from headers
        total_size_in_bytes: int = int(response.headers.get('content-length', 0))
        block_size: int = 8192  # 8 Kilobytes
        progress_bar = tqdm(total=total_size_in_bytes, unit='iB', unit_scale=True, desc=filename)

        # Save the file in chunks with progress bar
        with open(zip_path, "wb") as file:
            for chunk in response.iter_content(chunk_size=block_size):
                if chunk:  # filter out keep-alive new chunks
                    file.write(chunk)
                    progress_bar.update(len(chunk))
        progress_bar.close()
        print(f"\nФайл {filename} успешно загружен.")
        return zip_path
    else:
        print(f"Файл за дату {date.strftime('%Y-%m-%d')} не найден. Статус код: {response.status_code}")
        return None

def extract_files(zip_path: Path) -> Path:
    """
    Extract files from the given 7z archive using the password 'infected'.

    Args:
        zip_path (Path): The path to the 7z archive.

    Returns:
        Path: The directory where the files were extracted.
    """
    # Directory to extract files into, named after the archive without extension
    extract_dir: Path = Path("extracted_files") / zip_path.stem
    # Create the extraction directory if it doesn't exist
    extract_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        # Try to open and extract archive
        with py7zr.SevenZipFile(zip_path, mode='r', password='infected') as archive:
            archive.extractall(path=extract_dir)
        print(f"Файлы из {zip_path.name} извлечены в директорию {extract_dir}")
        return extract_dir

    except py7zr.Bad7zFile:
        print(f"Ошибка: архив '{zip_path.name}' поврежден или имеет неверный формат.")
        # Delete corrupted file
        try:
            os.remove(zip_path)
            print(f"Поврежденный файл '{zip_path.name}' удален.")
        except OSError as e:
            print(f"Ошибка при удалении файла '{zip_path.name}': {e}")
        return None

    except Exception as e:
        print(f"Неожиданная ошибка при извлечении архива: {e}")
        return None
