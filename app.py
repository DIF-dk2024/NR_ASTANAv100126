import os
import json
import uuid
import datetime as dt
import shutil
import re
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, send_from_directory, abort
)
from werkzeug.utils import secure_filename
from filelock import FileLock
from markupsafe import Markup, escape


# -----------------------------
# Config
# -----------------------------
DEFAULT_DATA_DIR = "/var/data"
DEFAULT_UPLOADS_DIR = "/var/data/uploads"

ALLOWED_EXTENSIONS = {
    # images
    "jpg", "jpeg", "png", "gif", "webp",
    # videos
    "mp4", "webm", "mov",
    # documents / archives (download-only)
    "pdf", "txt", "csv", "zip", "7z", "rar",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx",
}

# -----------------------------
# Special cards shown under 3 CTA buttons on the main page
# Stored as обычные карточки, но с полем special_key.
# -----------------------------
SPECIAL_CARD_SLOTS = [
    {"key": "telegram", "default_title": "Подписаться в Telegram"},
    {"key": "analytics", "default_title": "Персональная аналитика"},
    {"key": "course", "default_title": "Купить курс"},
]

def now_iso() -> str:
    return dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def refresh_card_files(app: Flask, card: dict) -> dict:
    """Rebuild file URLs from filename so they always work after deploy."""
    if not card or not isinstance(card, dict):
        return card
    cid = card.get("id") or ""
    files = []
    for f in (card.get("files") or []):
        if not isinstance(f, dict):
            continue
        name = f.get("name") or ""
        if not name:
            continue
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        files.append({
            "name": name,
            "ext": ext,
            "url": url_for("uploaded_file", card_id=cid, filename=name),
        })
    card["files"] = files
    return card

def ensure_special_cards(app: Flask) -> None:
    """Create the 3 special cards if they don't exist yet."""
    cards = load_cards(app)
    existing = {c.get("special_key") for c in cards if c.get("special_key")}
    used_ids = {c.get("id") for c in cards if c.get("id")}

    for slot in SPECIAL_CARD_SLOTS:
        key = slot["key"]
        if key in existing:
            continue

        # generate unique deterministic-length id (10 hex chars)
        card_id = uuid.uuid4().hex[:10]
        while card_id in used_ids:
            card_id = uuid.uuid4().hex[:10]

        card = {
            "id": card_id,
            "created_at": now_iso(),
            "title": slot["default_title"],
            "description": "",
            "files": [],
            "special_key": key,
        }
        append_card(app, card)
        used_ids.add(card_id)



def linkify_text(text: str):
    """Convert URLs in plain text to clickable links (safe HTML)."""
    if text is None:
        return ""
    s = str(text)

    # Matches:
    # - http(s)://...
    # - www....
    # - t.me/....
    # - bare domains like example.com/path
    url_re = re.compile(r'((?:https?://|www\.)[^\s<]+|t\.me/[^\s<]+|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?:/[^\s<]+)?)', re.IGNORECASE)

    out = []
    last = 0
    for m in url_re.finditer(s):
        start, end = m.span()
        out.append(escape(s[last:start]))

        raw = m.group(0)

        # strip trailing punctuation from the URL
        trail = ""
        while raw and raw[-1] in ".,;:!?)\]}>" :
            trail = raw[-1] + trail
            raw = raw[:-1]

        href = raw
        low = href.lower()
        if low.startswith("www."):
            href = "https://" + href
        elif low.startswith("t.me/"):
            href = "https://" + href
        elif not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", href):
            # bare domain without scheme
            href = "https://" + href

        out.append(Markup(f'<a href="{escape(href)}" target="_blank" rel="noopener">{escape(raw)}</a>{escape(trail)}'))
        last = end

    out.append(escape(s[last:]))
    return Markup("").join(out)



def create_app() -> Flask:
    app = Flask(__name__)

    # Jinja filter: make pasted URLs clickable
    app.jinja_env.filters["linkify"] = linkify_text

    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    app.config["ADMIN_PASSWORD"] = os.environ.get("ADMIN_PASSWORD", "")
    app.config["DATA_DIR"] = os.environ.get("DATA_DIR", DEFAULT_DATA_DIR)
    app.config["UPLOADS_DIR"] = os.environ.get("UPLOADS_DIR", DEFAULT_UPLOADS_DIR)

    # Upload limit (bytes). Example for ~30MB: 31457280
    app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_CONTENT_LENGTH", str(120 * 1024 * 1024)))  # 120 MB

    ensure_dirs(app)
    ensure_special_cards(app)
    @app.route("/")
    def index():
        all_cards = load_cards(app)

        special_keys = {s["key"] for s in SPECIAL_CARD_SLOTS}
        special_cards = {}
        cards = []

        for c in all_cards:
            key = c.get("special_key")
            c = refresh_card_files(app, c)
            if key in special_keys:
                special_cards[key] = c
            else:
                cards.append(c)

        cards.sort(key=lambda x: x.get("created_at", ""), reverse=True)

        # (на всякий случай) заполняем отсутствующие ключи заглушками,
        # чтобы шаблон не падал даже при повреждённом хранилище
        for slot in SPECIAL_CARD_SLOTS:
            special_cards.setdefault(slot["key"], {
                "id": "",
                "title": slot["default_title"],
                "description": "",
                "files": [],
            })

        return render_template("index.html", cards=cards, special_cards=special_cards, is_admin=is_admin())


    @app.route("/uploads/<card_id>/<path:filename>")
    def uploaded_file(card_id: str, filename: str):
        safe_card = sanitize_id(card_id)
        if not safe_card:
            abort(404)

        folder = os.path.join(app.config["UPLOADS_DIR"], safe_card)
        return send_from_directory(folder, filename, as_attachment=False)

    # -----------------------------
    # Admin auth
    # -----------------------------
    @app.route("/admin/login", methods=["GET", "POST"])
    def admin_login():
        if request.method == "POST":
            password = request.form.get("password", "")
            if not app.config["ADMIN_PASSWORD"]:
                flash("ADMIN_PASSWORD не задан. Укажи переменную окружения.", "error")
                return redirect(url_for("admin_login"))

            if password == app.config["ADMIN_PASSWORD"]:
                session["is_admin"] = True
                flash("Вход выполнен.", "ok")
                return redirect(url_for("admin_new"))

            flash("Неверный пароль.", "error")

        return render_template("admin_login.html", is_admin=is_admin())

    @app.route("/admin/logout")
    def admin_logout():
        session.pop("is_admin", None)
        flash("Вы вышли.", "ok")
        return redirect(url_for("index"))

    def admin_required(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not is_admin():
                return redirect(url_for("admin_login"))
            return fn(*args, **kwargs)
        return wrapper

    @app.route("/admin/new", methods=["GET", "POST"])
    @admin_required
    def admin_new():
        if request.method == "POST":
            title = (request.form.get("title") or "").strip()
            description = (request.form.get("description") or "").strip()
            files = request.files.getlist("files")

            if not title:
                flash("Заполни поле «Название».", "error")
                return redirect(url_for("admin_new"))

            card_id = uuid.uuid4().hex[:10]  # short id
            created_at = dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

            saved_files = []
            card_folder = os.path.join(app.config["UPLOADS_DIR"], card_id)
            os.makedirs(card_folder, exist_ok=True)

            for f in files:
                if not f or not getattr(f, "filename", ""):
                    continue
                original = f.filename
                filename = secure_filename(original)
                if not filename:
                    continue
                if not allowed_file(filename):
                    flash(f"Файл «{original}» отклонён: неподдерживаемое расширение.", "error")
                    continue

                filename = unique_filename(card_folder, filename)
                save_path = os.path.join(card_folder, filename)
                f.save(save_path)

                saved_files.append({
                    "name": filename,
                    "url": url_for("uploaded_file", card_id=card_id, filename=filename),
                    "ext": filename.rsplit(".", 1)[-1].lower()
                })

            card = {
                "id": card_id,
                "created_at": created_at,
                "title": title,
                "description": description,
                "files": saved_files,
            }

            append_card(app, card)
            flash("Карточка опубликована.", "ok")
            return redirect(url_for("index"))

        return render_template("admin_new.html", is_admin=is_admin())

    @app.post("/admin/delete/<card_id>")
    @admin_required
    def admin_delete(card_id: str):
        safe = sanitize_id(card_id)
        if not safe:
            abort(404)

        deleted = delete_card(app, safe)
        if not deleted:
            flash("Карточка не найдена.", "error")
            return redirect(url_for("index"))

        folder = os.path.join(app.config["UPLOADS_DIR"], safe)
        if os.path.isdir(folder):
            shutil.rmtree(folder, ignore_errors=True)

        flash("Карточка удалена.", "ok")
        return redirect(url_for("index"))



    @app.route("/admin/edit/<card_id>", methods=["GET", "POST"])
    @admin_required
    def admin_edit(card_id: str):
        safe = sanitize_id(card_id)
        if not safe:
            abort(404)

        card = get_card(app, safe)
        if not card:
            abort(404)

        if request.method == "POST":
            title = (request.form.get("title") or "").strip()
            description = (request.form.get("description") or "").strip()
            files = request.files.getlist("files")

            if not title:
                flash("Заполни поле «Название».", "error")
                return redirect(url_for("admin_edit", card_id=safe))

            # update fields
            card["title"] = title
            card["description"] = description

            # append newly uploaded files (allow multiple)
            saved_files = card.get("files") or []
            card_folder = os.path.join(app.config["UPLOADS_DIR"], safe)
            os.makedirs(card_folder, exist_ok=True)

            for f in files:
                if not f or not getattr(f, "filename", ""):
                    continue
                original = f.filename
                filename = secure_filename(original)
                if not filename:
                    continue
                if not allowed_file(filename):
                    flash(f"Файл «{original}» отклонён: неподдерживаемое расширение.", "error")
                    continue

                filename = unique_filename(card_folder, filename)
                save_path = os.path.join(card_folder, filename)
                f.save(save_path)

                saved_files.append({
                    "name": filename,
                    "url": url_for("uploaded_file", card_id=safe, filename=filename),
                    "ext": filename.rsplit(".", 1)[-1].lower()
                })

            card["files"] = saved_files

            if update_card(app, safe, card):
                flash("Карточка обновлена.", "ok")
            else:
                flash("Не удалось обновить карточку.", "error")

            return redirect(url_for("admin_edit", card_id=safe))

        return render_template("admin_edit.html", card=card, is_admin=is_admin())

    @app.post("/admin/delete-file/<card_id>")
    @admin_required
    def admin_delete_file(card_id: str):
        safe = sanitize_id(card_id)
        if not safe:
            abort(404)

        filename = request.form.get("filename", "")
        if not filename:
            flash("Файл не указан.", "error")
            return redirect(url_for("admin_edit", card_id=safe))

        ok = delete_file_from_card(app, safe, filename)
        if ok:
            flash("Файл удалён.", "ok")
        else:
            flash("Не удалось удалить файл.", "error")

        return redirect(url_for("admin_edit", card_id=safe))

    return app


# -----------------------------
# Helpers
# -----------------------------
def ensure_dirs(app: Flask) -> None:
    os.makedirs(app.config["DATA_DIR"], exist_ok=True)
    os.makedirs(app.config["UPLOADS_DIR"], exist_ok=True)

def sanitize_id(value: str) -> str:
    if not value:
        return ""
    value = value.lower()
    if all(c in "0123456789abcdef" for c in value) and 8 <= len(value) <= 32:
        return value
    return ""

def is_admin() -> bool:
    return bool(session.get("is_admin"))

def allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[-1].lower()
    return ext in ALLOWED_EXTENSIONS

def unique_filename(folder: str, filename: str) -> str:
    base, dot, ext = filename.rpartition(".")
    if not dot:
        base, ext = filename, ""
    candidate = filename
    i = 2
    while os.path.exists(os.path.join(folder, candidate)):
        candidate = f"{base}_{i}.{ext}" if ext else f"{base}_{i}"
        i += 1
    return candidate

def cards_csv_path(app: Flask) -> str:
    # фактически JSONL (по строке JSON на карточку), оставляем имя submissions.csv как привычное
    return os.path.join(app.config["DATA_DIR"], "submissions.csv")

def load_cards(app: Flask):
    path = cards_csv_path(app)
    if not os.path.exists(path):
        return []
    cards = []
    lock = FileLock(path + ".lock")
    with lock:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    cards.append(json.loads(line))
                except Exception:
                    continue
    return cards


def get_card(app: Flask, card_id: str):
    """Return a single card dict by id or None."""
    for c in load_cards(app):
        if c.get("id") == card_id:
            return c
    return None

def update_card(app: Flask, card_id: str, new_card: dict) -> bool:
    """Replace a card by id in submissions.csv (JSONL). Returns True if updated."""
    path = cards_csv_path(app)
    if not os.path.exists(path):
        return False

    lock = FileLock(path + ".lock")
    updated = False
    kept = []

    with lock:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue

                if obj.get("id") == card_id:
                    kept.append(json.dumps(new_card, ensure_ascii=False))
                    updated = True
                else:
                    kept.append(json.dumps(obj, ensure_ascii=False))

        with open(path, "w", encoding="utf-8") as f:
            for l in kept:
                f.write(l + "\n")

    return updated

def delete_file_from_card(app: Flask, card_id: str, filename: str) -> bool:
    """Delete a file from disk and remove it from card's file list. Returns True if deleted."""
    safe_id = sanitize_id(card_id)
    if not safe_id:
        return False

    safe_name = secure_filename(filename)
    if not safe_name:
        return False

    card = get_card(app, safe_id)
    if not card:
        return False

    files = card.get("files") or []
    # keep only entries not matching filename
    new_files = [f for f in files if f.get("name") != safe_name]
    if len(new_files) == len(files):
        return False  # not found in record

    # delete from disk (only within card folder)
    folder = os.path.join(app.config["UPLOADS_DIR"], safe_id)
    path = os.path.join(folder, safe_name)
    if os.path.exists(path):
        try:
            os.remove(path)
        except Exception:
            pass

    card["files"] = new_files
    return update_card(app, safe_id, card)

def append_card(app: Flask, card: dict) -> None:
    path = cards_csv_path(app)
    lock = FileLock(path + ".lock")
    with lock:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(card, ensure_ascii=False) + "\n")


def delete_card(app: Flask, card_id: str):
    """Delete a card by id from submissions.csv (JSONL). Returns deleted card dict or None."""
    path = cards_csv_path(app)
    if not os.path.exists(path):
        return None

    lock = FileLock(path + ".lock")
    deleted = None
    kept = []

    with lock:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue

                if obj.get("id") == card_id:
                    deleted = obj
                    continue

                kept.append(json.dumps(obj, ensure_ascii=False))

        with open(path, "w", encoding="utf-8") as f:
            for l in kept:
                f.write(l + "\n")

    return deleted


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=True)
