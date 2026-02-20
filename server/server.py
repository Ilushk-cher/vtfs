#!/usr/bin/env python3
import base64
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote_to_bytes

STATE_PATH = os.environ.get("VTFS_STATE", "./vtfs_state.json")
LISTEN_HOST = os.environ.get("VTFS_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("VTFS_PORT", "8080"))

LOCK = threading.Lock()

# ---------- binary reply: int64_le(rc) + payload ----------
def i64le(n: int) -> bytes:
    return int(n).to_bytes(8, "little", signed=True)

def ok(payload: bytes = b"") -> bytes:
    return i64le(0) + payload

def err(code: int) -> bytes:
    # positive errno-like code (kernel maps to -E*)
    return i64le(int(code))

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii")) if s else b""

def default_state():
    return {
        "next_ino": 101,
        "inodes": {
            "1000": {"type": "dir", "mode": 0o777}
        },
        "dentries": {
            "1000:/": 1000 # root
        }
    }

def load_state():
    if not os.path.exists(STATE_PATH):
        return default_state()
    with open(STATE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def save_state(st):
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, STATE_PATH)

STATE = load_state()

def ensure_root():
    global STATE
    if "inodes" not in STATE or "next_ino" not in STATE or "dentries" not in STATE:
        STATE = default_state()
        save_state(STATE)

ensure_root()


# ---------- helpers ----------
def get_inode(ino: int):
    return STATE["inodes"].get(str(ino))

def dentry_key(parent_ino: int, name: str) -> str:
    return f"{parent_ino}:{name}"

def find_dentry(parent_ino: int, name: str):
    key = dentry_key(parent_ino, name)
    target_ino = STATE["dentries"].get(key)
    if target_ino is None:
        return None, None
    return target_ino, get_inode(target_ino)

def list_dentries(parent_ino: int):
    prefix = f"{parent_ino}:"
    result = []
    for key, target_ino in STATE["dentries"].items():
        if key.startswith(prefix):
            name = key[len(prefix):]
            result.append((name, target_ino))
    return result

def alloc_ino(requested=None):
    ni = int(STATE.get("next_ino", 101))

    if requested is not None:
        r = int(requested)
        if str(r) not in STATE["inodes"]:
            if r >= ni:
                STATE["next_ino"] = r + 1
            return r

    while str(ni) in STATE["inodes"]:
        ni += 1
    STATE["next_ino"] = ni + 1
    return ni

def dump_state_payload() -> bytes:
    lines = []
    dentries = []
    for key, target_ino in STATE["dentries"].items():
        if ":" not in key:
            continue
        parent_ino, name = key.split(":", 1)
        parent_ino = int(parent_ino)
        
        inode = get_inode(target_ino)
        if not inode:
            continue
            
        if target_ino == 1000:
            continue
            
        if inode["type"] == "dir":
            lines.append(f"D\t{target_ino}\t{parent_ino}\t{name}\t{inode['mode']:#o}\n")
        elif inode["type"] == "file":
            data = b64d(inode.get("data_b64", ""))
            lines.append(f"F\t{target_ino}\t{parent_ino}\t{name}\t{inode['mode']:#o}\t{len(data)}\n")
    
    for key, target_ino in STATE["dentries"].items():
        if ":" not in key:
            continue
        parent_ino, name = key.split(":", 1)
        parent_ino = int(parent_ino)
        
        inode = get_inode(target_ino)
        if not inode or inode["type"] != "file":
            continue
            
        primary_key = dentry_key(parent_ino, name)
        if STATE["dentries"].get(primary_key) == target_ino:
            continue
        else:
            lines.append(f"L\t{target_ino}\t{parent_ino}\t{name}\t{target_ino}\n")
    
    return "".join(lines).encode("utf-8")


# ---------- HTTP handler ----------
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            u = urlparse(self.path)
            if not u.path.startswith("/api/"):
                self._reply(404, b"")
                return

            method = u.path[len("/api/"):]
            q = parse_qs(u.query, keep_blank_values=True)

            token = (q.get("token", [""])[0] or "").strip()
            if token == "":
                self._send_bin(err(7))
                return

            with LOCK:
                ensure_root()
                resp = self.dispatch(method, q)
                self._send_bin(resp)
        except Exception as e:
            print(f"Exception: {e}")
            self._send_bin(err(8))

    def dispatch(self, method: str, q: dict) -> bytes:
        # --- dump ---
        if method == "dump":
            return ok(dump_state_payload())

        # --- mkdir ---
        if method == "mkdir":
            parent = int(q.get("parent", ["0"])[0])
            name = q.get("name", [""])[0]
            ino_req = q.get("ino", [None])[0]
            mode = int(q.get("mode", ["511"])[0]) & 0o777

            parent_inode = get_inode(parent)
            if not parent_inode:
                return err(1)  # ENOENT
            if parent_inode["type"] != "dir":
                return err(3)  # ENOTDIR
            
            if name == "" or "/" in name:
                return err(7)  # EINVAL
            
            ex_ino, _ = find_dentry(parent, name)
            if ex_ino is not None:
                return err(2)  # EEXIST

            ino = alloc_ino(ino_req)
            STATE["inodes"][str(ino)] = {"type": "dir", "mode": mode}
            
            STATE["dentries"][dentry_key(parent, name)] = ino
            
            save_state(STATE)
            return ok(f"ino={ino}\n".encode("utf-8"))

        # --- create ---
        if method == "create":
            parent = int(q.get("parent", ["0"])[0])
            name = q.get("name", [""])[0]
            ino_req = q.get("ino", [None])[0]
            mode = int(q.get("mode", ["511"])[0]) & 0o777

            parent_inode = get_inode(parent)
            if not parent_inode:
                return err(1)
            if parent_inode["type"] != "dir":
                return err(3)
            
            if name == "" or "/" in name:
                return err(7)
            
            ex_ino, _ = find_dentry(parent, name)
            if ex_ino is not None:
                return err(2)

            ino = alloc_ino(ino_req)
            STATE["inodes"][str(ino)] = {
                "type": "file", 
                "mode": mode, 
                "data_b64": "",
                "nlink": 1
            }
            
            STATE["dentries"][dentry_key(parent, name)] = ino
            
            save_state(STATE)
            return ok(f"ino={ino}\n".encode("utf-8"))

        # --- link ---
        if method == "link":
            parent = int(q.get("parent", ["0"])[0])
            name = q.get("name", [""])[0]
            target_ino = int(q.get("target", ["0"])[0])

            parent_inode = get_inode(parent)
            if not parent_inode or parent_inode["type"] != "dir":
                return err(3)
            
            target_inode = get_inode(target_ino)
            if not target_inode:
                return err(1)
            if target_inode["type"] == "dir":
                return err(6)  # EPERM
            
            if name == "" or "/" in name:
                return err(7)
            
            ex_ino, _ = find_dentry(parent, name)
            if ex_ino is not None:
                return err(2)

            STATE["dentries"][dentry_key(parent, name)] = target_ino
            
            if target_inode["type"] == "file":
                target_inode["nlink"] = target_inode.get("nlink", 1) + 1
            
            save_state(STATE)
            return ok()

        # --- unlink ---
        if method == "unlink":
            parent = int(q.get("parent", ["0"])[0])
            name = q.get("name", [""])[0]

            parent_inode = get_inode(parent)
            if not parent_inode or parent_inode["type"] != "dir":
                return err(3)

            target_ino, target_inode = find_dentry(parent, name)
            if target_ino is None:
                return err(1)
            
            if target_inode["type"] == "dir":
                if list_dentries(target_ino):
                    return err(5)  # ENOTEMPTY

            key = dentry_key(parent, name)
            del STATE["dentries"][key]
            
            if target_inode["type"] == "file":
                target_inode["nlink"] = target_inode.get("nlink", 1) - 1
                
                if target_inode["nlink"] <= 0:
                    del STATE["inodes"][str(target_ino)]
            
            save_state(STATE)
            return ok()

        # --- rmdir ---
        if method == "rmdir":
            parent = int(q.get("parent", ["0"])[0])
            name = q.get("name", [""])[0]

            parent_inode = get_inode(parent)
            if not parent_inode or parent_inode["type"] != "dir":
                return err(3)

            target_ino, target_inode = find_dentry(parent, name)
            if target_ino is None:
                return err(1)
            
            if target_inode["type"] != "dir":
                return err(3)  # ENOTDIR

            if list_dentries(target_ino):
                return err(5)  # ENOTEMPTY

            key = dentry_key(parent, name)
            del STATE["dentries"][key]
            
            del STATE["inodes"][str(target_ino)]
            
            save_state(STATE)
            return ok()

        # --- truncate ---
        if method == "truncate":
            ino = int(q.get("ino", ["0"])[0])
            size = int(q.get("size", ["0"])[0])

            inode = get_inode(ino)
            if not inode:
                return err(1)
            if inode["type"] == "dir":
                return err(4)  # EISDIR

            data = b64d(inode.get("data_b64", ""))
            if size <= 0:
                data = b""
            else:
                if size < len(data):
                    data = data[:size]
                else:
                    data = data + (b"\x00" * (size - len(data)))
            inode["data_b64"] = b64e(data) if data else ""
            save_state(STATE)
            return ok()

        # --- write ---
        if method == "write":
            ino = int(q.get("ino", ["0"])[0])
            off = int(q.get("off", ["0"])[0])
            data_param = q.get("data", [""])[0]

            inode = get_inode(ino)
            if not inode:
                return err(1)
            if inode["type"] == "dir":
                return err(4)
            if off < 0:
                return err(7)

            chunk = unquote_to_bytes(data_param)
            cur = b64d(inode.get("data_b64", ""))

            if off > len(cur):
                cur = cur + (b"\x00" * (off - len(cur)))

            new = cur[:off] + chunk
            if off + len(chunk) < len(cur):
                new += cur[off + len(chunk):]

            inode["data_b64"] = b64e(new) if new else ""
            save_state(STATE)
            return ok()

        # --- read ---
        if method == "read":
            ino = int(q.get("ino", ["0"])[0])
            off = int(q.get("off", ["0"])[0])
            ln = int(q.get("len", ["0"])[0])

            inode = get_inode(ino)
            if not inode:
                return err(1)
            if inode["type"] == "dir":
                return err(4)
            if off < 0 or ln < 0:
                return err(7)

            data = b64d(inode.get("data_b64", ""))
            if off >= len(data):
                return ok(b"")
            return ok(data[off:off + ln])

        return err(7)

    def _send_bin(self, body: bytes):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _reply(self, code: int, body: bytes):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        super().log_message(fmt, *args)


def main():
    print(f"VTFS server listening on {LISTEN_HOST}:{LISTEN_PORT}, state={STATE_PATH}")
    HTTPServer((LISTEN_HOST, LISTEN_PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()