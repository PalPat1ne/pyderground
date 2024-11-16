# download_files.py

import requests
from pathlib import Path
from datetime import datetime
from typing import Optional

def download_file(date: datetime) -> Optional[Path]:
    base_url = "https://samples.vx-underground.org/Samples/VirusSign%20Collection/"
    folder = date.strftime('%Y.%m')  # Формат папки: YYYY.MM
    filename = f"Virussign.{date.strftime('%Y.%m.%d')}.7z"  # Формат файла: Virussign.YYYY.MM.DD.7z
    url = f"{base_url}{folder}/{filename}"

    zip_path = Path("downloads") / filename  # Сохраняем файл в папку 'downloads'
    zip_path.parent.mkdir(exist_ok=True)

    # Проверка, если файл уже существует
    if zip_path.exists():
        print(f"Файл {filename} уже загружен ранее.")
        return zip_path

    response = requests.get(url, stream=True)

    if response.status_code == 200:
        with open(zip_path, "wb") as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)
        print(f"Файл {filename} успешно загружен.")
        return zip_path
    else:
        print(f"Файл за дату {date.strftime('%Y-%m-%d')} не найден. Статус код: {response.status_code}")
    return None

def extract_files(zip_path: Path) -> Path:
    extract_dir = Path("extracted_files") / zip_path.stem  # Директория для распаковки каждого архива
    extract_dir.mkdir(parents=True, exist_ok=True)

    import py7zr  # Библиотека для работы с 7z архивами
    with py7zr.SevenZipFile(zip_path, mode='r', password='infected') as z:
        z.extractall(path=extract_dir)
    print(f"Файлы из {zip_path.name} извлечены в директорию {extract_dir}")
    return extract_dir
