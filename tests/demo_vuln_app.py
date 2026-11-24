"""Deliberately vulnerable DEMO app — for allscan's own tests and demos only.

Binds to 127.0.0.1. Nothing here is real: SQL "errors", template evaluation,
file errors and stack traces are simulated strings. Run it standalone with
``python tests/demo_vuln_app.py 8080`` or use :func:`make_server` in tests.
"""
import re, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

class H(BaseHTTPRequestHandler):
    server_version = "DemoVuln/1.0"
    def log_message(self, *a): pass
    def _send(self, code, body, headers=None):
        b = body.encode()
        self.send_response(code)
        for k, v in (headers or {}).items(): self.send_header(k, v)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        if self.command != "HEAD": self.wfile.write(b)
    def do_OPTIONS(self):
        self._send(200, "", {"Allow": "GET, POST, PUT, DELETE, TRACE, OPTIONS"})
    def do_TRACE(self):
        self._send(200, "".join(f"{k}: {v}\n" for k, v in self.headers.items()), {"Content-Type": "message/http"})
    def do_GET(self):
        u = urlparse(self.path); q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
        raw = u.query
        p = u.path
        h = {"Access-Control-Allow-Origin": self.headers.get("Origin", "*"), "Access-Control-Allow-Credentials": "true"}
        if p == "/.env": return self._send(200, "DB_PASSWORD=hunter2\n", h)
        if p == "/.git/HEAD": return self._send(200, "ref: refs/heads/main\n", h)
        if p == "/phpinfo.php": return self._send(200, "<title>phpinfo()</title>PHP Version 7.4", h)
        if p == "/actuator/env": return self._send(200, '{"activeProfiles":["prod"]}', h)
        if p == "/server-status": return self._send(200, "Apache Server Status", h)
        if p == "/redirect":
            return self._send(302, "", {"Location": q.get("next", "/")})
        if p == "/search":
            s = q.get("q", "")
            # CRLF: honour encoded CRLF in raw query
            m = re.search(r"%0d%0a(X-Allscan-Crlf):([0-9a-f]+)", raw, re.I)
            if m: h[m.group(1)] = m.group(2)
            ev = s.replace("{{7*7}}", "49")  # fake template eval
            return self._send(200, f"<html><body>You searched: {ev}</body></html>", h)
        if p == "/item":
            i = q.get("id", "1")
            if "'" in i and "AND" not in i:
                return self._send(500, "You have an error in your SQL syntax; check the manual near ''' at line 1", h)
            if "AND '1'='2" in i: return self._send(200, "<html>no rows</html>", h)
            if "AND '1'='1" in i: return self._send(200, "<html>Item 1: Widget price $9.99 in stock now!!</html>", h)
            return self._send(200, "<html>Item 1: Widget price $9.99 in stock now!!</html>", h)
        if p == "/file":
            f = q.get("name", "a.txt")
            if f.startswith(".."): return self._send(200, "Warning: include(): failed to open stream: No such file or directory in /var/www/html/file.php", h)
            return self._send(200, "file ok", h)
        if p == "/boom":
            if "allscanq=%00" in raw: return self._send(500, "Traceback (most recent call last):\n  File app.py, line 9\nValueError", h)
            return self._send(200, "ok", h)
        if p not in ('/', '/index.html'): return self._send(404, 'not found', h)
        body = ('<html><head><title>Demo Shop</title></head><body>Welcome '
                '<a href="http://127.0.0.1:%d/search?q=hi">search</a> '
                '<a href="http://127.0.0.1:%d/item?id=1">item</a> '
                '<a href="http://127.0.0.1:%d/redirect?next=/">go</a> '
                '<a href="http://127.0.0.1:%d/file?name=a.txt">file</a> '
                '<a href="http://127.0.0.1:%d/boom?x=1">boom</a>'
                '</body></html>') % ((self.server.server_port,) * 5)
        self._send(200, body, h)

def make_server(port: int = 0) -> ThreadingHTTPServer:
    """Create (not start) the demo server; ``port=0`` picks a free port."""
    return ThreadingHTTPServer(("127.0.0.1", port), H)


if __name__ == "__main__":
    make_server(int(sys.argv[1]) if len(sys.argv) > 1 else 8080).serve_forever()
