"""Prove the image trusts a certificate authority the specification imported.

The certificate files arrive as artifacts; the root itself arrives through
`filesystem.ca`. The bundle Vapor wrote is loaded explicitly, so a handshake with a
certificate that root signed succeeds only if the root is really in the bundle.

A second context trusts an unrelated certificate instead. It has to reject the same
server: without that, a client that skipped verification would look like a pass.
"""

import socket
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

BUNDLE = "/etc/ssl/certs/ca-certificates.crt"
SERVER_CERT = "/app/ca/server.pem"
SERVER_KEY = "/app/ca/server.key"
UNTRUSTED = "/app/ca/untrusted.pem"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"trusted\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


def serve():
    """Runs the server until the process exits, on a port the kernel picks."""
    server = HTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(SERVER_CERT, SERVER_KEY)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server.server_address[1]


def fetch(context, port):
    """Returns the body, or the verification error the handshake raised."""
    with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
        try:
            with context.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
                tls.sendall(b"GET / HTTP/1.0\r\n\r\n")
                # One recv can return headers only, so read until the peer closes.
                body = b""
                while chunk := tls.recv(4096):
                    body += chunk
                return body, None
        except ssl.SSLCertVerificationError as error:
            return None, error


def main():
    port = serve()

    trusted = ssl.create_default_context(cafile=BUNDLE)
    body, error = fetch(trusted, port)
    if error is not None:
        raise SystemExit(f"the imported root did not verify the server: {error}")
    if b"trusted" not in body:
        raise SystemExit(f"unexpected response: {body!r}")

    unrelated = ssl.create_default_context(cafile=UNTRUSTED)
    _, error = fetch(unrelated, port)
    if error is None:
        raise SystemExit("a context trusting an unrelated certificate accepted the server")

    sys.stdout.write("tls ok\n")


if __name__ == "__main__":
    main()
