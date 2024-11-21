# Автоматизация с использованием Airflow

Для автоматизации процессов загрузки, сканирования и сохранения файлов, в проекте используется интеграция с **Apache Airflow**. Это позволяет создать DAG, который управляет заданиями, обеспечивая планирование и автоматическое выполнение всех этапов обработки.

## Быстрый старт

### Предварительные требования

- **Python 3.9+**
- **Docker и Docker Compose**

### Установка

1. **Клонируйте репозиторий**:
   
   ```bash
   git clone https://github.com/PalPat1ne/pyderground.git
   cd pyderground
   ```
2. **Смените ветку на Airflow_Dag**:
   ```bash
   git checkout Airflow_Dag
   ```

3. **Установите права доступа для папок**:
   ```bash
   sudo chown -R :5000 app dags logs plugins
   sudo chmod -R 777 app dags logs plugins
   ```

4. **Запустите контейнеры с помощью Docker Compose**:
   ```bash
   docker-compose -f docker-compose.airflow.yml up -d
   ```
5. **Создайте пользователя для Airflow Веб интерфейса**
   ```bash
   docker exec -it airflow-scheduler airflow users create \
    --username admin \
    --firstname Admin \
    --lastname User \
    --role Admin \
    --email admin@example.com \
    --password yourpassword
   ```
6. **Убедитесь, что MinIO работает** на порту `9000`     (API) и веб-интерфейс доступен на порту `9001`.    Перейдите по адресу `http://localhost:9001` и   используйте учетные данные по умолчанию:
   - **Пользователь**: `minioadmin`
   - **Пароль**: `minioadmin`

7. **Проверьте работу Airflow** на порту `8080`
   Перейдите по адресу `http://localhost:8080` и используйте учетные данные по которые вводили в пункте 5
   - **Пользователь**: `Admin`
   - **Пароль**: `yourpassword`

### Использование

- **Запуск DAG вручную**:
  ```bash
  docker exec -it airflow-scheduler airflow dags test vx_underground_processing yyyy-mm-dd
  ```
  Замените `yyyy-mm-dd` на нужную дату в формате `год-месяц-день`.

## Доступ к интерфейсу Airflow и MinIO

- **Airflow**: доступен по адресу `http://localhost:8080`.
- **MinIO**: доступен по адресу `http://localhost:9001`.

