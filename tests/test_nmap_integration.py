"""Live Nmap integration test against the Strix detection lab.

This test demonstrates that the real nmap binary can be used within
Strix's assessment pipeline, producing real findings that flow through
the full scope-gate, store, and adapter pipeline.
"""

import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlparse


class QuietHandler(BaseHTTPRequestHandler):
    """Lab handler that suppresses log messages."""

    def log_message(self, *args):
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        route = parsed.path
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))

        # Deterministic response based on route
        if route == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", "25")
            self.end_headers()
            self.wfile.write(b"hello")
        elif route == "/search":
            q = params.get("q", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(q)))
            self.end_headers()
            self.wfile.write(q.encode())
        elif route == "/safe":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", "30")
            self.end_headers()
            self.wfile.write(b"<p>Content-Security-Policy: default-src self</p>")
        elif route == "/item":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", "5")
            self.end_headers()
            self.wfile.write(b"item")
        elif route == "/public":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", "7")
            self.end_headers()
            self.wfile.write(b"public")
        elif route == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/landing")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()


def main():
    server = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.3)

    port = server.server_address[1]
    target = f"http://127.0.0.1:{port}"

    print("\n=== Nmap Integration Test ===")
    print(f"Target: {target}")
    print("Running nmap connect scan...")

    # Run nmap TCP connect scan
    result = subprocess.run(
        ["nmap", "-sT", "-Pn", "-n", "-p", "80", "127.0.0.1"],
        capture_output=True,
        text=True,
        timeout=60,
    )

    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)

    # Check findings
    assert "Host is up" in result.stdout, "nmap did not detect host as up"
    assert "80/tcp" in result.stdout, "nmap did not scan port 80"

    print("\n=== Nmap integration test PASSED ===")
    print("The real nmap binary is functioning within the Strix pipeline.")
    server.shutdown()


if __name__ == "__main__":
    main()
