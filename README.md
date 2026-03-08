# PDS

Автоматизированный сканер подозрительных доменов для кейса по анализу фишинга.

## Возможности

- чтение списка доменов из `input/domains.txt`
- поиск ключевых слов: `bank`, `login`, `secure`, `account`, `verify`, `update`, `confirm`
- поиск поддоменов через `subfinder`
- WHOIS-анализ
- SSL-проверка
- интеграция с VirusTotal и Shodan при наличии API-ключей
- расчёт `suspicion_score`
- формирование:
  - `output/report.csv`
  - `output/report.json`

## Запуск через Docker

```bash
docker compose up --build
