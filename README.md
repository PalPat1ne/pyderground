# Pyderground

Этот проект представляет собой утилиту для загрузки и обработки вредоносных файлов с сервиса VX Underground, их сканирования с использованием YARA-правил и сохранения результатов в S3-хранилище (MinIO).

## Основные функции

- **Скачивание файлов** за указанный день с сервиса VX Underground.
- **Извлечение файлов** из архивов и их сохранение в S3-хранилище (MinIO).
- **Сканирование файлов** с использованием YARA-правил для обнаружения вредоносных объектов.
- **Сохранение результатов** сканирования в формате JSON в S3-хранилище.

## Автоматизация с использованием Airflow

Для автоматизации процессов загрузки, сканирования и сохранения файлов, в проекте существует ветка **`Airflow_Dag`**, в которой реализована интеграция с **Apache Airflow**. Это позволяет создать DAG, который будет управлять заданиями, обеспечивая планирование и автоматическое выполнение всех этапов обработки.

Если вам необходима автоматизация, переключитесь на ветку `Airflow_Dag`:
```bash
git checkout Airflow_Dag
```
С этой веткой вы сможете автоматически выполнять все действия по загрузке и обработке файлов, используя инфраструктуру Apache Airflow.

## Структура проекта

```plaintext
vx_underground_processor/
├── src/                           # Основные скрипты
│   ├── download_files.py          # Скачивание и извлечение файлов
│   ├── s3_upload.py               # Загрузка файлов в S3
│   ├── yara_scan.py               # Сканирование YARA
├── yara_rules/                    # YARA-правила
│   └── rules.yar                  # Пример YARA-правил
├── pyproject.toml                 # Файл зависимостей для Poetry
├── docker-compose.yml             # Docker Compose файл для MinIO
├── main.py                        # main.py основной файл для запуска
└── README.md                      # Документация проекта
```

## Быстрый старт

### Предварительные требования

- **Poetry** (для управления зависимостями)
- **Python 3.9+**
- **Docker и Docker Compose**
- **Poetry** (для управления зависимостями)

### Установка Poetry

Установите Poetry с помощью pip:
```bash
pip install poetry
```

### Установка

1. **Клонируйте репозиторий**:
   ```bash
   git clone https://github.com/PalPat1ne/pyderground.git
   cd pyderground
   ```

2. **Создайте виртуальное окружение и установите зависимости** с помощью Poetry:
   ```bash
   python3 -m venv .
   ```
   ```bash
   source ./bin/activate
   ```
   ```bash
   poetry install
   ```

3. **Установите и запустите MinIO** с помощью Docker Compose:
   ```bash
   docker-compose up -d
   ```

4. **Убедитесь, что MinIO работает** на порту `9000` (API) и веб-интерфейс доступен на порту `9001` по умолчанию. Перейдите по адресу `http://localhost:9001` и используйте учетные данные по умолчанию:
   - **Пользователь**: `minioadmin`
   - **Пароль**: `minioadmin`

### Использование

1. **Запустите основной скрипт для обработки файлов вручную**:
   ```bash
   python main.py YYYY-MM-DD
   ```
   Замените `YYYY-MM-DD` на дату, за которую хотите скачать и обработать файлы.

### Структура работы

1. **Скачивание файлов**: Скрипт `download_files.py` формирует URL на основе переданной даты, загружает и сохраняет архив.
2. **Извлечение файлов**: Архив распаковывается в директорию `extracted_files`.
3. **Сканирование YARA-правилами**: Все извлеченные файлы сканируются с использованием правил из директории `yara_rules`. Результаты сохраняются в формате JSON.
4. **Загрузка в S3**: Извлеченные файлы и результаты сканирования загружаются в MinIO с помощью `s3_upload.py`.

### Примечания по безопасности

- **Работа с вредоносными файлами**: Убедитесь, что выполнение этого проекта происходит в безопасной среде, например, в виртуальной машине или контейнере, чтобы предотвратить заражение основной системы.
- **Пароль для архивов**: VX Underground файлы могут быть защищены паролем. По умолчанию используется пароль `infected` для распаковки архивов.

### Дополнительные зависимости

Файл `pyproject.toml` содержит список всех необходимых зависимостей, включая:
- **requests**: для скачивания файлов с веб-сервиса.
- **boto3**: для работы с S3 (MinIO).
- **yara-python**: для интеграции с YARA.
- **py7zr**: для работы с архивами формата `7z`.

### Лицензия

Проект распространяется под лицензией MIT. Более подробная информация находится в файле LICENSE.

### Контакты

- Автор: PalPat1ne
- GitHub: [https://github.com/PalPat1ne](https://github.com/PalPat1ne)

Если у вас возникли вопросы или предложения, пожалуйста, создайте issue на GitHub или свяжитесь со мной напрямую.

