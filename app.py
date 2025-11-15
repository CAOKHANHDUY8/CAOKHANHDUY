# app.py
import os
import io
import sqlite3
from pathlib import Path
from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    session, send_file, abort
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# --------------------
# Config
# --------------------
BASE_DIR = Path(__file__).parent
UPLOAD_DIR = BASE_DIR / "uploads"
DB_PATH = BASE_DIR / "app.db"
ALLOWED_EXT = {".bytes"}

UPLOAD_DIR.mkdir(exist_ok=True)

SECRET_KEY = "change_this_to_a_random_secret_in_production"

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["UPLOAD_FOLDER"] = str(UPLOAD_DIR)

# --------------------
# DB helpers (very small wrapper)
# --------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        stored_name TEXT NOT NULL,
        hex TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )""")
    conn.commit()
    conn.close()

def db_execute(query, args=(), fetch=False, many=False):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    if many:
        cur.executemany(query, args)
        conn.commit()
        conn.close()
        return None
    cur.execute(query, args)
    rows = cur.fetchall() if fetch else None
    conn.commit()
    conn.close()
    return rows

# --------------------
# Utility functions (ported from main2.py)
# --------------------
def to_hex_string(data: bytes) -> str:
    return ''.join(f"{b:02X}" for b in data)

def from_hex_string(hexstr: str) -> bytes:
    return bytes.fromhex(hexstr)

def find_last_index_of_pattern_between(hexstr, start, end):
    last_start_index = hexstr.rfind(start)
    if last_start_index == -1: return None
    end_index = hexstr.find(end, last_start_index + len(start))
    if end_index == -1: return None
    return (last_start_index, end_index + len(end))

def extract_uid_from_hex(hexstr, start, end):
    pos = find_last_index_of_pattern_between(hexstr, start, end)
    if not pos:
        return None
    s, e = pos
    bytes_hex = hexstr[s + len(start): e - len(end)]
    if not bytes_hex or all(c == '0' for c in bytes_hex):
        return None
    return bytes_hex

def hex_to_uleb128_number(hex_uid):
    bytes_data = from_hex_string(hex_uid)
    result = 0
    shift = 0
    for b in bytes_data:
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
    return result

def encodeULEB128(value: int) -> bytes:
    result = []
    while True:
        byte = value & 0x7F
        value >>= 7
        if value != 0:
            byte |= 0x80
        result.append(byte)
        if value == 0:
            break
    return bytes(result)

def delete_uid(hexstr, start, end):
    pos = find_last_index_of_pattern_between(hexstr, start, end)
    if not pos:
        return None
    s, e = pos
    bytes_hex = hexstr[s + len(start): e - len(end)]
    if all(c == '0' for c in bytes_hex):
        return None  # already deleted
    replacement = start + '00' + end
    return hexstr[:s] + replacement + hexstr[e:]

def edit_uid(hexstr, start, end, new_uid_hex):
    pos = find_last_index_of_pattern_between(hexstr, start, end)
    if not pos:
        return None
    s, e = pos
    bytes_hex = hexstr[s + len(start): e - len(end)]
    length_to_replace = e - s - len(start) - len(end)
    if all(c == '0' for c in bytes_hex):
        replacement = start + new_uid_hex + end
        return hexstr[:s] + replacement + hexstr[e:]
    else:
        if len(new_uid_hex) < length_to_replace:
            new_uid_hex = new_uid_hex.ljust(length_to_replace, '0')
        else:
            new_uid_hex = new_uid_hex[:length_to_replace]
        replacement = start + new_uid_hex + end
        return hexstr[:s] + replacement + hexstr[e:]

# Map edit helpers
TEAM_PREFIX = bytes.fromhex('09090018')
PLAYER_PREFIX = bytes.fromhex('09008199')
ROUND_PREFIX = bytes.fromhex('99990118')

team_map = {
    i: bytes.fromhex(f"{i:02X}") if i <= 9 else bytes.fromhex(f"0{chr(55 + i)}") for i in range(1, 13)
}
player_map = team_map.copy()
round_map = {i: bytes([i]) if i <= 9 else bytes([0x0A + i - 10]) for i in range(1, 21)}

def replace_value(buffer: bytearray, prefix: bytes, new_val: bytes) -> bool:
    prefix_len = len(prefix)
    for i in range(len(buffer) - prefix_len -1):
        if buffer[i:i+prefix_len] == prefix:
            buffer[i+prefix_len] = new_val[0]
            return True
    return False

# UID anchors (same as bot)
UID_START = 'A203'
UID_END = '03'

# --------------------
# Auth helpers
# --------------------
def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    rows = db_execute("SELECT id, username FROM users WHERE id = ?", (user_id,), fetch=True)
    if not rows: return None
    uid, username = rows[0]
    return {"id": uid, "username": username}

# --------------------
# Routes
# --------------------
@app.route("/")
def home():
    user = current_user()
    return render_template("index.html", user=user)

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username","" ).strip()
        password = request.form.get("password","" )
        if not username or not password:
            flash("Vui lòng nhập username và password", "danger")
            return redirect(url_for("register"))
        hashed = generate_password_hash(password)
        try:
            db_execute("INSERT INTO users (username,password) VALUES (?,?)", (username, hashed))
        except Exception as e:
            flash("Tên người dùng đã tồn tại.", "danger")
            return redirect(url_for("register"))
        flash("Đăng ký thành công. Đăng nhập bây giờ.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","" ).strip()
        password = request.form.get("password","" )
        rows = db_execute("SELECT id,password FROM users WHERE username = ?", (username,), fetch=True)
        if not rows:
            flash("Người dùng không tồn tại", "danger")
            return redirect(url_for("login"))
        uid, hashed = rows[0]
        if not check_password_hash(hashed, password):
            flash("Mật khẩu không chính xác", "danger")
            return redirect(url_for("login"))
        session["user_id"] = uid
        flash("Đăng nhập thành công", "success")
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Đã đăng xuất", "info")
    return redirect(url_for("home"))

@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    rows = db_execute("SELECT id,filename,stored_name,created_at FROM files WHERE user_id = ? ORDER BY id DESC", (user["id"],), fetch=True)
    files = [{"id":r[0],"filename":r[1],"stored_name":r[2],"created_at":r[3]} for r in rows] if rows else []
    return render_template("dashboard.html", user=user, files=files)

# Upload endpoint
@app.route("/upload", methods=["POST"])
def upload():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    f = request.files.get("file")
    if not f:
        flash("Vui lòng chọn file .bytes", "danger")
        return redirect(url_for("dashboard"))
    fn = secure_filename(f.filename)
    ext = Path(fn).suffix.lower()
    if ext not in ALLOWED_EXT:
        flash("Chỉ chấp nhận .bytes files", "danger")
        return redirect(url_for("dashboard"))
    stored = f"{user['id']}_{int(os.times()[4]*1000)}_{fn}"
    path = UPLOAD_DIR / stored
    f.save(path)
    # compute hex and store in DB
    data = path.read_bytes()
    hexstr = to_hex_string(data)
    db_execute("INSERT INTO files (user_id,filename,stored_name,hex) VALUES (?,?,?,?)", (user["id"], fn, stored, hexstr))
    flash("Upload thành công", "success")
    return redirect(url_for("dashboard"))

# View file details and actions
@app.route("/file/<int:file_id>")
def file_detail(file_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    rows = db_execute("SELECT id,filename,stored_name,hex FROM files WHERE id = ? AND user_id = ?", (file_id, user["id"]), fetch=True)
    if not rows:
        abort(404)
    fid, filename, stored_name, hexstr = rows[0]
    uid_hex = extract_uid_from_hex(hexstr, UID_START, UID_END)
    uid_val = hex_to_uleb128_number(uid_hex) if uid_hex else None
    return render_template("upload_result.html", user=user, file={"id":fid,"filename":filename,"stored_name":stored_name,"hex":hexstr,"uid_hex":uid_hex,"uid_val":uid_val})

# Edit UID (form POST)
@app.route("/file/<int:file_id>/edit_uid", methods=["GET","POST"])
def file_edit_uid(file_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    rows = db_execute("SELECT id,filename,stored_name,hex FROM files WHERE id = ? AND user_id = ?", (file_id, user["id"]), fetch=True)
    if not rows:
        abort(404)
    fid, filename, stored_name, hexstr = rows[0]
    if request.method == "POST":
        new_uid_str = request.form.get("new_uid","" ).strip()
        try:
            new_uid = int(new_uid_str)
        except:
            flash("UID phải là số nguyên", "danger")
            return redirect(url_for("file_edit_uid", file_id=file_id))
        uid_bytes = encodeULEB128(new_uid)
        new_uid_hex = to_hex_string(uid_bytes)
        new_hex = edit_uid(hexstr, UID_START, UID_END, new_uid_hex)
        if new_hex is None:
            flash("Không tìm thấy vùng UID để sửa", "danger")
            return redirect(url_for("file_detail", file_id=file_id))
        new_data = from_hex_string(new_hex)
        out_name = f"edited_{filename}"
        return send_file(io.BytesIO(new_data), download_name=out_name, as_attachment=True)
    # GET -> show form
    return render_template("edit_uid.html", user=user, file={"id":fid,"filename":filename})

# Delete UID (POST)
@app.route("/file/<int:file_id>/delete_uid", methods=["POST"])
def file_delete_uid(file_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    rows = db_execute("SELECT id,filename,stored_name,hex FROM files WHERE id = ? AND user_id = ?", (file_id, user["id"]), fetch=True)
    if not rows:
        abort(404)
    fid, filename, stored_name, hexstr = rows[0]
    new_hex = delete_uid(hexstr, UID_START, UID_END)
    if new_hex is None:
        flash("UID đã bị xóa hoặc không tìm thấy", "warning")
        return redirect(url_for("file_detail", file_id=file_id))
    new_data = from_hex_string(new_hex)
    out_name = f"deleted_{filename}"
    return send_file(io.BytesIO(new_data), download_name=out_name, as_attachment=True)

# Edit map (POST form)
@app.route("/file/<int:file_id>/edit_map", methods=["GET","POST"])
def file_edit_map(file_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    rows = db_execute("SELECT id,filename,stored_name,hex FROM files WHERE id = ? AND user_id = ?", (file_id, user["id"]), fetch=True)
    if not rows:
        abort(404)
    fid, filename, stored_name, hexstr = rows[0]
    stored_path = UPLOAD_DIR / stored_name
    if not stored_path.exists():
        flash("File gốc không tồn tại trên server", "danger")
        return redirect(url_for("file_detail", file_id=file_id))
    if request.method == "POST":
        try:
            team = int(request.form.get("team"))
            player = int(request.form.get("player"))
            rnd = int(request.form.get("round"))
        except:
            flash("Vui lòng chọn team/player/round hợp lệ", "danger")
            return redirect(url_for("file_edit_map", file_id=file_id))
        # load bytes and make replacements
        buf = bytearray(stored_path.read_bytes())
        team_hex = team_map.get(team)
        player_hex = player_map.get(player)
        round_hex = round_map.get(rnd)
        replaced_team = replace_value(buf, TEAM_PREFIX, team_hex)
        replaced_player = replace_value(buf, PLAYER_PREFIX, player_hex)
        replaced_round = replace_value(buf, ROUND_PREFIX, round_hex)
        out_name = filename.replace(".bytes","_mapedited.bytes")
        return send_file(io.BytesIO(bytes(buf)), download_name=out_name, as_attachment=True)
    # GET -> form
    return render_template("edit_map.html", user=user, file={"id":fid,"filename":filename})

# --------------------
# Start
# --------------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
