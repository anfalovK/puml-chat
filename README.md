# puml-chat

## Описание
Веб-приложение для генерации PlantUML-диаграмм из текстового описания на естественном языке. Работает через llm-gateway с каскадным вызовом LLM-моделей.

## Статус
🟢 Живой (production) — puml.axelper.pro

## Стек
- **Backend:** Python (Flask)
- **Frontend:** HTML + JS (vanilla)
- **LLM Gateway:** llm-gateway (127.0.0.1:8330) — каскад GPT-4o-mini → Qwen3.8 → DeepSeek
- **Auth:** axelper-auth (регистрация/логин/тарифы)
- **Прокси:** nginx (puml.axelper.pro → core:3012)

## Быстрый старт
```bash
git clone https://task.axelper.com/aXelper/puml-chat.git
cd puml-chat
cp env.example .env
# Настроить LLM_BASE_URL и API-ключи
python3 app.py
```

## Деплой
- **Сервер:** core (135.106.199.249), порт 3012
- **Домен:** https://puml.axelper.pro
- **Service:** systemd `puml-web-server.service`
- **Config:** `/opt/puml-web-server/env`
- **Nginx:** upstream → localhost:3012

## Тарифы
- **Free:** 10 диаграмм/день
- **Pro:** расширенные лимиты (через axelper-auth)
- **Enterprise:** безлимит, все модели

## API
- `GET /` — главная страница
- `POST /generate` — генерация диаграммы по тексту
- `POST /chat` — диалоговый режим
- `POST /refine` — уточнение диаграммы
- `GET /api/admin/account` — админка (статистика)
- `POST /api/admin/reset` — сброс дневных лимитов

## Структура репозитория
```
app.py          — backend Flask-приложение
env.example     — пример конфигурации
data/           — данные и кэш
```

## Авторы
aXelper (Константин Анфалов)
