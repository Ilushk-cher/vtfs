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
        "nodes": {
            "1000": {"type": "dir", "parent": 1000, "name": "/", "mode": 0o777}
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
    if "nodes" not in STATE or "next_ino" not in STATE or "1000" not in STATE["nodes"]:
        STATE = default_state()
        save_state(STATE)

ensure_root()


# ---------- helpers ----------
def resolve_node(ino: int):
    n = STATE["nodes"].get(str(ino))
    if not n:
        return None
    if n["type"] == "link":
        tgt = int(n["target"])
        return STATE["nodes"].get(str(tgt))
    return n

def find_child(parent_ino: int, name: str):
    for ino_s, n in STATE["nodes"].items():
        if int(n.get("parent", -1)) == parent_ino and n.get("name") == name:
            return int(ino_s), n
    return None, None

def alloc_ino(requested):
    ni = int(STATE.get("next_ino", 101))

    if requested is not None:
        r = int(requested)
        if str(r) not in STATE["nodes"]:
            if r >= ni:
                STATE["next_ino"] = r + 1
        return r

    while str(ni) in STATE["nodes"]:
        ni += 1
    STATE["next_ino"] = ni + 1
    return ni

def node_depth(ino: int, max_hops: int = 4096) -> int:
    # depth from root(1000): root children => 1
    d = 0
    cur = ino
    seen = set()
    for _ in range(max_hops):
        if cur == 1000:
            return d
        if cur in seen:
            return 10**9
        seen.add(cur)
        n = STATE["nodes"].get(str(cur))
        if not n:
            return 10**9
        cur = int(n.get("parent", 1000))
        d += 1
    return 10**9

def list_dir_payload(dir_ino: int) -> bytes:
    # "name\tino\ttype\n" ; for link output target ino as ino (hardlink semantics)
    out = []
    for ino_s, n in STATE["nodes"].items():
        if int(n.get("parent", -1)) != dir_ino:
            continue
        t = n["type"]
        if t == "dir":
            out.append(f"{n['name']}\t{ino_s}\tdir\n")
        elif t == "file":
            out.append(f"{n['name']}\t{ino_s}\treg\n")
        else:  # link
            out.append(f"{n['name']}\t{int(n['target'])}\treg\n")
    return "".join(out).encode("utf-8")

def dump_state_payload() -> bytes:
    """
    IMPORTANT: emit parents before children, otherwise kernel restore skips entries.
    Order:
      - dirs by depth asc
      - files by depth asc
      - links last
    """
    items = list(STATE["nodes"].items())

    def key(kv):
        ino_s, n = kv
        ino = int(ino_s)
        t = n.get("type")
        depth = node_depth(ino)
        t_rank = 0 if t == "dir" else (1 if t == "file" else 2)
        return (depth, t_rank, int(n.get("parent", 0)), n.get("name", ""), ino)

    items.sort(key=key)

    lines = []
    for ino_s, n in items:
        ino = int(ino_s)
        if ino == 1000:
            continue
        t = n["type"]
        pino = int(n["parent"])
        name = n["name"]
        mode = int(n.get("mode", 0o777))

        if t == "dir":
            lines.append(f"D\t{ino}\t{pino}\t{name}\t{mode:#o}\n")
        elif t == "file":
            data = b64d(n.get("data_b64", ""))
            lines.append(f"F\t{ino}\t{pino}\t{name}\t{mode:#o}\t{len(data)}\n")
        else:  # link
            # dump format your kernel expects:
            # L \t ino \t pino \t name \t target_ino
            lines.append(f"L\t{ino}\t{pino}\t{name}\t{int(n['target'])}\n")

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
        except Exception:
            self._send_bin(err(8))

    def dispatch(self, method: str, q: dict) -> bytes:
        # --- dump ---
        if method == "dump":
            return ok(dump_state_payload())

        # --- list ---
        if method == "list":
            dir_ino = int(q.get("dir", ["0"])[0])
            n = resolve_node(dir_ino)
            if not n:
                return err(1)  # ENOENT
            if n["type"] != "dir":
                return err(3)  # ENOTDIR
            return ok(list_dir_payload(dir_ino))

        # --- lookup ---
        if method == "lookup":
            parent = int(q.get("parent", ["0"])[0])
            name = q.get("name", [""])[0]
            pn = resolve_node(parent)
            if not pn:
                return err(1)
            if pn["type"] != "dir":
                return err(3)
            cino, cn = find_child(parent, name)
            if not cn:
                return err(1)
            if cn["type"] == "dir":
                out = f"ino={cino}\ttype=dir\tmode={int(cn.get('mode',0o777))}\n".encode("utf-8")
            elif cn["type"] == "file":
                out = f"ino={cino}\ttype=reg\tmode={int(cn.get('mode',0o777))}\n".encode("utf-8")
            else:  # link -> target ino
                out = f"ino={int(cn['target'])}\ttype=reg\tmode=511\n".encode("utf-8")
            return ok(out)

        # --- mkdir ---
        if method == "mkdir":
            parent = int(q.get("parent", ["0"])[0])
            name = q.get("name", [""])[0]
            ino_req = q.get("ino", [None])[0]
            mode = int(q.get("mode", ["511"])[0]) & 0o777

            pn = resolve_node(parent)
            if not pn:
                return err(1)
            if pn["type"] != "dir":
                return err(3)
            if name == "" or "/" in name:
                return err(7)
            ex, _ = find_child(parent, name)
            if ex is not None:
                return err(2)  # EEXIST

            ino = alloc_ino(ino_req)
            STATE["nodes"][str(ino)] = {"type": "dir", "parent": parent, "name": name, "mode": mode}
            save_state(STATE)
            return ok(f"ino={ino}\n".encode("utf-8"))

        # --- create ---
        if method == "create":
            parent = int(q.get("parent", ["0"])[0])
            name = q.get("name", [""])[0]
            ino_req = q.get("ino", [None])[0]
            mode = int(q.get("mode", ["511"])[0]) & 0o777

            pn = resolve_node(parent)
            if not pn:
                return err(1)
            if pn["type"] != "dir":
                return err(3)
            if name == "" or "/" in name:
                return err(7)
            ex, _ = find_child(parent, name)
            if ex is not None:
                return err(2)

            ino = alloc_ino(ino_req)
            STATE["nodes"][str(ino)] = {"type": "file", "parent": parent, "name": name, "mode": mode, "data_b64": ""}
            save_state(STATE)
            return ok(f"ino={ino}\n".encode("utf-8"))

        # --- unlink ---
        if method == "unlink":
            parent = int(q.get("parent", ["0"])[0])
            name = q.get("name", [""])[0]

            pn = resolve_node(parent)
            if not pn:
                return err(1)
            if pn["type"] != "dir":
                return err(3)

            cino, cn = find_child(parent, name)
            if not cn:
                return err(1)
            if cn["type"] == "dir":
                return err(4)  # EISDIR

            # remove entry; keep target file node if other links exist (simple refcount)
            if cn["type"] == "file":
                target_ino = cino
            else:  # link
                target_ino = int(cn["target"])

            del STATE["nodes"][str(cino)]

            # if target is a file, delete it only if no one references it (incl. file itself)
            if str(target_ino) in STATE["nodes"] and STATE["nodes"][str(target_ino)]["type"] == "file":
                still_ref = False
                for ino_s2, n2 in STATE["nodes"].items():
                    if n2["type"] == "file" and int(ino_s2) == target_ino:
                        still_ref = True
                        break
                    if n2["type"] == "link" and int(n2["target"]) == target_ino:
                        still_ref = True
                        break
                if not still_ref:
                    STATE["nodes"].pop(str(target_ino), None)

            save_state(STATE)
            return ok()

        # --- rmdir ---
        if method == "rmdir":
            parent = int(q.get("parent", ["0"])[0])
            name = q.get("name", [""])[0]

            pn = resolve_node(parent)
            if not pn:
                return err(1)
            if pn["type"] != "dir":
                return err(3)

            cino, cn = find_child(parent, name)
            if not cn:
                return err(1)
            if cn["type"] != "dir":
                return err(3)

            # check empty
            for _, n in STATE["nodes"].items():
                if int(n.get("parent", -1)) == cino:
                    return err(5)  # ENOTEMPTY

            del STATE["nodes"][str(cino)]
            save_state(STATE)
            return ok()

        # --- truncate ---
        if method == "truncate":
            ino = int(q.get("ino", ["0"])[0])
            size = int(q.get("size", ["0"])[0])

            n = resolve_node(ino)
            if not n:
                return err(1)
            if n["type"] == "dir":
                return err(4)

            data = b64d(n.get("data_b64", ""))
            if size <= 0:
                data = b""
            else:
                if size < len(data):
                    data = data[:size]
                else:
                    data = data + (b"\x00" * (size - len(data)))
            n["data_b64"] = b64e(data) if data else ""
            save_state(STATE)
            return ok()

        # --- write ---
        if method == "write":
            ino = int(q.get("ino", ["0"])[0])
            off = int(q.get("off", ["0"])[0])
            data_param = q.get("data", [""])[0]

            n = resolve_node(ino)
            if not n:
                return err(1)
            if n["type"] == "dir":
                return err(4)
            if off < 0:
                return err(7)

            chunk = unquote_to_bytes(data_param)
            cur = b64d(n.get("data_b64", ""))

            if off > len(cur):
                cur = cur + (b"\x00" * (off - len(cur)))

            new = cur[:off] + chunk
            if off + len(chunk) < len(cur):
                new += cur[off + len(chunk):]

            n["data_b64"] = b64e(new) if new else ""
            save_state(STATE)
            return ok()

        # --- read ---
        if method == "read":
            ino = int(q.get("ino", ["0"])[0])
            off = int(q.get("off", ["0"])[0])
            ln = int(q.get("len", ["0"])[0])

            n = resolve_node(ino)
            if not n:
                return err(1)
            if n["type"] == "dir":
                return err(4)
            if off < 0 or ln < 0:
                return err(7)

            data = b64d(n.get("data_b64", ""))
            if off >= len(data):
                return ok(b"")
            return ok(data[off:off + ln])

        # --- link ---
        if method == "link":
            old = int(q.get("old", ["0"])[0])
            parent = int(q.get("parent", ["0"])[0])
            name = q.get("name", [""])[0]

            pn = resolve_node(parent)
            if not pn or pn["type"] != "dir":
                return err(3)

            tn = resolve_node(old)
            if not tn:
                return err(1)
            if tn["type"] == "dir":
                return err(6)  # EPERM

            ex, _ = find_child(parent, name)
            if ex is not None:
                return err(2)

            link_id = alloc_ino(None)
            STATE["nodes"][str(link_id)] = {"type": "link", "parent": parent, "name": name, "target": old}
            save_state(STATE)
            return ok()

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
