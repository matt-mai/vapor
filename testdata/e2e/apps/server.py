"""Minimal HTTP server used to prove a built image actually runs.

Standard library only, so the same file runs from a whole-package image, a
sliced image and (via a compiled equivalent) an artifact image.
"""

import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(os.environ.get("PORT", "8080"))


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            body = b"ok"
        else:
            body = b"hello from vapor\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(fmt % args, file=sys.stderr)


if __name__ == "__main__":
    print(f"listening on {PORT}", file=sys.stderr)
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
