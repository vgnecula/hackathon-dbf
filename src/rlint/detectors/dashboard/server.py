"""Serve the generated rlint dashboard without adding a web-framework dependency."""

from __future__ import annotations

import argparse
import json
import threading
import webbrowser
from collections.abc import Sequence
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from urllib.parse import urlsplit

from .payload import report_payload

_ROUTES = {
    "/": ("index.dc.html", "text/html; charset=utf-8"),
    "/index.html": ("index.dc.html", "text/html; charset=utf-8"),
    "/console": ("console.dc.html", "text/html; charset=utf-8"),
    "/console.html": ("console.dc.html", "text/html; charset=utf-8"),
    "/support.js": ("support.js", "text/javascript; charset=utf-8"),
}
_BOOT_TAG = b'<script src="./support.js"></script>'


def asset_for_path(path: str) -> tuple[bytes, str] | None:
    """Return a dashboard asset for an exact public route."""
    route = _ROUTES.get(path)
    if route is None:
        return None
    name, content_type = route
    content = files(__package__).joinpath(name).read_bytes()
    return content, content_type


def product_payload() -> dict[str, object]:
    """Run the real detector registry over the canonical product rollouts."""
    from ...report import demo_rollouts
    from ..registry import build_report

    rollouts = demo_rollouts()
    return report_payload(build_report("csv_stats", rollouts))


def dashboard_asset_for_path(path: str) -> tuple[bytes, str] | None:
    """Inject the current product report into generated HTML views."""
    asset = asset_for_path(path)
    if asset is None:
        return None
    body, content_type = asset
    if not content_type.startswith("text/html"):
        return asset
    encoded = json.dumps(product_payload(), separators=(",", ":")).replace("</", "<\\/")
    bootstrap = f"<script>window.__RLINT_DATA__={encoded};</script>".encode()
    return body.replace(_BOOT_TAG, bootstrap + _BOOT_TAG, 1), content_type


class DashboardHandler(BaseHTTPRequestHandler):
    """Allowlisted dashboard server backed by the detector/report pipeline."""

    server_version = "rlint-dashboard/0.1"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if urlsplit(self.path).path == "/api/report":
            self._send_json(product_payload())
            return
        self._send_asset(include_body=True)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if urlsplit(self.path).path == "/api/run":
            self._send_json(product_payload())
            return
        self._send_not_found(include_body=True)

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if urlsplit(self.path).path == "/api/report":
            self._send_json(product_payload(), include_body=False)
            return
        self._send_asset(include_body=False)

    def _send_asset(self, *, include_body: bool) -> None:
        asset = dashboard_asset_for_path(urlsplit(self.path).path)
        if asset is None:
            self._send_not_found(include_body=include_body)
            return
        body, content_type = asset
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def _send_json(self, payload: object, *, include_body: bool = True) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def _send_not_found(self, *, include_body: bool) -> None:
        body = b"Not found\n"
        self.send_response(HTTPStatus.NOT_FOUND)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def serve(
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    open_browser: bool = True,
) -> None:
    """Serve until interrupted, optionally opening the report in a browser."""
    server = ThreadingHTTPServer((host, port), DashboardHandler)
    actual_port = server.server_address[1]
    display_host = "127.0.0.1" if host in {"0.0.0.0", "::"} else host
    url = f"http://{display_host}:{actual_port}/"
    console_url = f"{url}console"
    print(f"rlint dashboard: {url}")
    print(f"rlint console:   {console_url}")
    if open_browser:
        threading.Timer(0.15, webbrowser.open, args=(url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Preview the rlint detector dashboard.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-open", action="store_true", help="do not open a browser")
    args = parser.parse_args(argv)
    serve(host=args.host, port=args.port, open_browser=not args.no_open)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
