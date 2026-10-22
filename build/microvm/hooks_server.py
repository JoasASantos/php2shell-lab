#!/usr/bin/env python3
"""CourseStack hooks server — health check and status endpoint."""

import http.server
import json
import subprocess
import os

PORT = 7681


class HooksHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health" or self.path == "/":
            status = self._check_services()
            code = 200 if status["healthy"] else 503
            self._json_response(code, status)
        elif self.path == "/info":
            self._json_response(200, {
                "name": "php2shell-lab",
                "description": "PHP2Shell (CVE-2026-109618/619) exploitation lab",
                "services": ["apache2", "mariadb"],
                "credentials": {
                    "wordpress": {"user": "admin", "pass": "admin123", "url": "/wp-admin/"},
                },
                "exploit_entry": "/health.php",
            })
        else:
            self._json_response(404, {"error": "not found"})

    def _check_services(self):
        apache = self._proc_running("apache2")
        mariadb = self._proc_running("mariadbd")
        return {
            "healthy": apache and mariadb,
            "services": {
                "apache2": "running" if apache else "stopped",
                "mariadb": "running" if mariadb else "stopped",
            },
        }

    def _proc_running(self, name):
        try:
            subprocess.check_output(["pgrep", "-x", name], stderr=subprocess.DEVNULL)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def _json_response(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    server = http.server.HTTPServer(("0.0.0.0", PORT), HooksHandler)
    print(f"[hooks] Listening on port {PORT}")
    server.serve_forever()
