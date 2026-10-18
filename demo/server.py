"""Synthetic-only fixture. Not exposed on host ports."""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json


class Demo(BaseHTTPRequestHandler):
    def do_GET(self):
        role = self.headers.get("X-Test-Account", "anonymous")
        if self.path == "/public":
            status, body = 200, {"message": "public synthetic page"}
        elif self.path == "/fixture/shared":
            status, body = (
                200,
                {
                    "fixture": "synthetic shared data; inspect expected permission matrix"
                },
            )
        elif self.path == "/secure/admin":
            status, body = (
                (200, {"fixture": "synthetic admin data"})
                if role == "admin"
                else (403, {"error": "forbidden"})
            )
        else:
            status, body = 404, {"error": "not found"}
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        if self.path.startswith("/secure"):
            self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Demo).serve_forever()
