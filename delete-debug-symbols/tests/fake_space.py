#!/usr/bin/env python3
"""Minimal stand-in for a DO Space: serves GET and DELETE over a directory.

Usage: fake_space.py <root> <port>

A key whose name contains "forbidden" answers 403, so the error path can be
exercised. Deletes are idempotent, the way S3 behaves.
"""
import http.server
import os
import sys

ROOT = os.path.abspath(sys.argv[1])
PORT = int(sys.argv[2])


class Handler(http.server.BaseHTTPRequestHandler):
    def _local_path(self):
        return os.path.join(ROOT, self.path.lstrip("/").split("?")[0])

    def _empty(self, status):
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        path = self._local_path()
        if "forbidden" in self.path:
            return self._empty(403)
        if not os.path.isfile(path):
            return self._empty(404)
        with open(path, "rb") as handle:
            body = handle.read()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_DELETE(self):
        if "forbidden" in self.path:
            return self._empty(403)
        path = self._local_path()
        if os.path.isfile(path):
            os.remove(path)
        self._empty(204)

    def log_message(self, *args):
        pass


http.server.HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
