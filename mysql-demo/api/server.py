"""Tiny users CRUD API in front of MySQL - no framework, no C
dependencies (pymysql is pure Python, vendored under ./vendor since
kiln's build sandbox has no network access for `pip install`; see
mysql-demo/README.md). Connects to MySQL on startup (retrying, since
the mysql container's own first-boot init can take a while) and creates
the users table if it doesn't exist yet.
"""

import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

sys.path.insert(0, "/vendor")
import pymysql  # noqa: E402

DB_HOST = os.environ.get("DB_HOST", "mysql")
DB_PORT = int(os.environ.get("DB_PORT", "3306"))
DB_USER = os.environ.get("DB_USER", "demo")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "demo")
DB_NAME = os.environ.get("DB_NAME", "kiln_demo")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8081"))


def connect_with_retry(attempts=30, delay=2):
    last_err = None
    for i in range(attempts):
        try:
            conn = pymysql.connect(
                host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD, database=DB_NAME, autocommit=True
            )
            print(f"connected to mysql after {i + 1} attempt(s)", flush=True)
            return conn
        except Exception as e:  # noqa: BLE001 - genuinely want to retry on anything here
            last_err = e
            print(f"mysql not ready yet ({e}), retrying in {delay}s...", flush=True)
            time.sleep(delay)
    raise RuntimeError(f"could not connect to mysql after {attempts} attempts: {last_err}")


def init_schema(conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) NOT NULL
            )
            """
        )


def row_to_dict(row):
    return {"id": row[0], "name": row[1], "email": row[2]}


class Handler(BaseHTTPRequestHandler):
    conn = None  # set in main()

    def _send_json(self, status, body):
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length))

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/users":
            with self.conn.cursor() as cur:
                cur.execute("SELECT id, name, email FROM users ORDER BY id")
                rows = cur.fetchall()
            self._send_json(200, [row_to_dict(r) for r in rows])
            return
        if path == "/health":
            self._send_json(200, {"ok": True})
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/users":
            body = self._read_json()
            name, email = body.get("name", "").strip(), body.get("email", "").strip()
            if not name or not email:
                self._send_json(400, {"error": "name and email are required"})
                return
            with self.conn.cursor() as cur:
                cur.execute("INSERT INTO users (name, email) VALUES (%s, %s)", (name, email))
                new_id = cur.lastrowid
            self._send_json(201, {"id": new_id, "name": name, "email": email})
            return
        self._send_json(404, {"error": "not found"})

    def do_PUT(self):
        path = urlparse(self.path).path
        parts = path.strip("/").split("/")
        if len(parts) == 2 and parts[0] == "users" and parts[1].isdigit():
            user_id = int(parts[1])
            body = self._read_json()
            name, email = body.get("name", "").strip(), body.get("email", "").strip()
            if not name or not email:
                self._send_json(400, {"error": "name and email are required"})
                return
            with self.conn.cursor() as cur:
                cur.execute("UPDATE users SET name = %s, email = %s WHERE id = %s", (name, email, user_id))
                if cur.rowcount == 0:
                    self._send_json(404, {"error": "no such user"})
                    return
            self._send_json(200, {"id": user_id, "name": name, "email": email})
            return
        self._send_json(404, {"error": "not found"})

    def do_DELETE(self):
        path = urlparse(self.path).path
        parts = path.strip("/").split("/")
        if len(parts) == 2 and parts[0] == "users" and parts[1].isdigit():
            user_id = int(parts[1])
            with self.conn.cursor() as cur:
                cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
                if cur.rowcount == 0:
                    self._send_json(404, {"error": "no such user"})
                    return
            self._send_json(200, {"ok": True})
            return
        self._send_json(404, {"error": "not found"})

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}", flush=True)


def main():
    conn = connect_with_retry()
    init_schema(conn)
    Handler.conn = conn
    server = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler)
    print(f"listening on 0.0.0.0:{LISTEN_PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
