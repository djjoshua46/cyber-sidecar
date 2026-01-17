from __future__ import annotations
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse


def make_csv(rows: int) -> bytes:
    # header + rows
    out = ["id,value"]
    for i in range(1, rows + 1):
        out.append(f"{i},row_{i}")
    return ("\n".join(out) + "\n").encode("utf-8")


SMALL = make_csv(5)
MEDIUM = make_csv(800)
HUGE = make_csv(20000)  # "huge" — tune later if you want bigger


class Handler(BaseHTTPRequestHandler):
    server_version = "SidecarUpstreamMock/1.0"

    def _send(self, code: int, body: bytes, content_type: str = "text/plain; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/health":
            return self._send(200, b"ok\n")

        if path == "/export/small.csv":
            return self._send(200, SMALL, "text/csv; charset=utf-8")

        if path == "/export/medium.csv":
            return self._send(200, MEDIUM, "text/csv; charset=utf-8")

        if path == "/export/huge.csv":
            # optional artificial delay to simulate “big export”
            # time.sleep(0.25)
            return self._send(200, HUGE, "text/csv; charset=utf-8")

        return self._send(404, f"not found: {path}\n".encode("utf-8"))

    def do_HEAD(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            return

        if self.path.startswith("/export/"):
            # Just return headers; don't send body
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.end_headers()
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        # keep it quiet (comment out if you want request logs)
        return


def main():
    host = "127.0.0.1"
    port = 8099
    httpd = HTTPServer((host, port), Handler)
    print(f"[upstream_mock] listening on http://{host}:{port}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
