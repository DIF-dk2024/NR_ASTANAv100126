# Статичтика Квадратных Метров — карточки (публикация только админ)

Простая Flask-доска карточек:
- Публичная страница со списком карточек (**Название**, **Описание**, вложения).
- **Создание новой карточки — только админ** (пароль из `ADMIN_PASSWORD`).
- Вложения: **файлы и видео** (mp4/webm/mov + изображения + документы).
- Хранение данных и загрузок — на **Render Persistent Disk** (`/var/data`).

## Где что лежит
- Карточки: `/var/data/submissions.csv` (по строке JSON на карточку)
- Файлы: `/var/data/uploads/<card_id>/<file>`

## Переменные окружения
- `SECRET_KEY` — для Flask-сессии
- `ADMIN_PASSWORD` — пароль админки
- `DATA_DIR` — папка данных (на Render: `/var/data`)
- `UPLOADS_DIR` — папка загрузок (на Render: `/var/data/uploads`)
- `MAX_CONTENT_LENGTH` — лимит размера запроса (в байтах), например 31457280 (~30MB)

## Локальный запуск
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt

set SECRET_KEY=dev
set ADMIN_PASSWORD=1234
python app.py
```

Открой: http://127.0.0.1:5000

## Deploy на Render
1) Залей репозиторий на GitHub  
2) Render → New → Web Service → выбери репо  
3) Render автоматически подхватит `render.yaml`  
4) В Environment добавь `SECRET_KEY` и `ADMIN_PASSWORD`

Админка:
- `/admin/login` — вход
- `/admin/new` — новая карточка


## Админ-функции
- `/admin/new` — новая карточка
- `/admin/edit/<id>` — редактирование (название/описание, добавление файлов)
- Удаление файла: кнопка на странице редактирования
