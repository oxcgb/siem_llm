# SOC LLM Analyzer v1.0

## Быстрый старт
1. `bash bootstrap.sh` — создаст проект
2. `./start.sh` — скачает модель, сгенерирует .env, поднимет стек
3. Консоль: `http://localhost/` (логин/пароль из вывода start.sh)

## Dev-режим
- api: `cd api && BACKEND_API_KEY=devkey uvicorn main:app --port 8001`
- frontend: `BACKEND_API_KEY=devkey npm run dev`

## Заметки
- Положите `GeoLite2-City.mmdb` в `data/` (или `GEO_LICENSE_KEY` в `.env`)
- В проде: `SIEM_VERIFY=/путь/к/CA.pem`
- При ошибке vLLM со fp8 — уберите `--kv-cache-dtype fp8` из compose
