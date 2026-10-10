#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本地 mock 登录服务：仅供 web_bruter 端到端测试。
GET /login  -> 登录表单（含一次性 user_token）
POST /login -> token 错误：'CSRF token is incorrect'；密码错误：'Login failed'；
               正确（admin/password123）：302 -> /welcome（含 'Welcome, admin'）
"""
import secrets
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

CORRECT_USER = "admin"
CORRECT_PWD = "password123"
_last_token = {"value": None}
_lock = threading.Lock()

FORM = """<html><body>
<form method="post" action="/login">
<input type="text" name="username" value="">
<input type="password" name="password" value="">
<input type="hidden" name="user_token" value="{token}">
<input type="submit" value="Login">
</form></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, headers=None):
        data = body.encode("utf-8")
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.startswith("/login"):
            token = secrets.token_hex(8)
            with _lock:
                _last_token["value"] = token
            self._send(200, FORM.format(token=token))
        elif self.path.startswith("/welcome"):
            self._send(200, "<html>Welcome, admin</html>")
        else:
            self._send(404, "not found")

    def do_POST(self):
        if not self.path.startswith("/login"):
            self._send(404, "not found")
            return
        length = int(self.headers.get("Content-Length", 0))
        params = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"))
        user = params.get("username", [""])[0]
        pwd = params.get("password", [""])[0]
        token = params.get("user_token", [""])[0]
        with _lock:
            expected = _last_token["value"]
            _last_token["value"] = None  # 一次性 token
        if token != expected:
            self._send(200, "CSRF token is incorrect")
            return
        if user == CORRECT_USER and pwd == CORRECT_PWD:
            self._send(302, "", {"Location": "/welcome"})
        else:
            self._send(200, "Login failed")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18080
    srv = HTTPServer(("127.0.0.1", port), Handler)
    print(f"mock server on 127.0.0.1:{port}", flush=True)
    srv.serve_forever()
