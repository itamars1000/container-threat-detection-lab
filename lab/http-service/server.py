"""Small HTTP target for controlled lab requests."""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SERVICE_NAME = os.environ.get("SERVICE_NAME", "allowed-api")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        healthy = self.path == "/health"
        payload = {"service": SERVICE_NAME, "status": "ok" if healthy else "not_found"}
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200 if healthy else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    print(f"{SERVICE_NAME} listening on port 8080", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
