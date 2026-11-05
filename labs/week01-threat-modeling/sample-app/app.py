"""
Tiny sample web app for Week 1 threat modeling.
You will NOT exploit this in Week 1 - you will draw a data-flow diagram
and apply STRIDE to its components (web client, app, SQLite DB, /upload).

wk01 fix (student: 66991016): user-supplied filenames never become path
components. Uploads are stored under a server-generated UUID name, the
original name is kept only as metadata, and /files/<name> serves the
stored name after a strict pattern check + DB lookup.
"""
from flask import Flask, request, jsonify, send_from_directory, abort
import sqlite3, os, re, uuid, logging

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MiB upload cap (DoS)
DB = "notes.db"
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
ALLOWED_EXT = {"txt", "md", "pdf", "png", "jpg", "jpeg"}
STORED_NAME_RE = re.compile(r"^[0-9a-f]{32}\.[a-z0-9]{1,5}$")

logging.basicConfig(filename="app.log", level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")

os.makedirs(UPLOAD_DIR, exist_ok=True)

def init_db():
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, owner TEXT, body TEXT)")
    con.execute("CREATE TABLE IF NOT EXISTS uploads ("
                "id INTEGER PRIMARY KEY, stored_name TEXT UNIQUE, "
                "original_name TEXT, size INTEGER, uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP)")
    con.commit(); con.close()

@app.route("/notes", methods=["GET", "POST"])
def notes():
    con = sqlite3.connect(DB)
    if request.method == "POST":
        owner = request.json.get("owner", "anon")
        body = request.json.get("body", "")
        logging.info("notes_write owner=%s ip=%s", owner, request.remote_addr)
        con.execute("INSERT INTO notes (owner, body) VALUES (?, ?)", (owner, body))
        con.commit()
    rows = con.execute("SELECT id, owner, body FROM notes").fetchall()
    con.close()
    return jsonify(rows)

@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if f is None or not f.filename:
        abort(400, "file field required")
    # Validate only on data we can reason about - never on a path.
    original = os.path.basename(f.filename.replace("\\", "/"))
    if "." not in original:
        abort(400, "filename must have an extension")
    ext = original.rsplit(".", 1)[1].lower()
    if ext not in ALLOWED_EXT:
        abort(400, "extension not allowed")
    # The stored name is generated here, not supplied by the client.
    stored_name = f"{uuid.uuid4().hex}.{ext}"
    dest = os.path.join(UPLOAD_DIR, stored_name)
    f.save(dest)
    con = sqlite3.connect(DB)
    con.execute("INSERT INTO uploads (stored_name, original_name, size) VALUES (?, ?, ?)",
                (stored_name, original, os.path.getsize(dest)))
    con.commit(); con.close()
    logging.info("upload stored=%s original=%s ip=%s", stored_name, original, request.remote_addr)
    return {"id": stored_name, "original": original}

@app.route("/files/<name>")
def files(name):
    # Whitelist the shape first, then confirm the record exists.
    if not STORED_NAME_RE.match(name):
        abort(404)
    con = sqlite3.connect(DB)
    row = con.execute("SELECT stored_name FROM uploads WHERE stored_name = ?", (name,)).fetchone()
    con.close()
    if row is None:
        abort(404)
    return send_from_directory(UPLOAD_DIR, name)

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
