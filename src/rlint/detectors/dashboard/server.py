"""Serve the generated rlint dashboard without adding a web-framework dependency."""

from __future__ import annotations

import argparse
import json
import os
import threading
import webbrowser
from collections.abc import Sequence
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from urllib.parse import parse_qs, urlsplit

from .payload import report_payload

_ROUTES = {
    "/": ("index.dc.html", "text/html; charset=utf-8"),
    "/index.html": ("index.dc.html", "text/html; charset=utf-8"),
    "/console": ("console.dc.html", "text/html; charset=utf-8"),
    "/console.html": ("console.dc.html", "text/html; charset=utf-8"),
    "/support.js": ("support.js", "text/javascript; charset=utf-8"),
}
_BOOT_TAG = b'<script src="./support.js"></script>'
DEFAULT_ENV_ID = "csv_stats"
DEFAULT_GRADING = "inband"


def asset_for_path(path: str) -> tuple[bytes, str] | None:
    """Return a dashboard asset for an exact public route."""
    route = _ROUTES.get(path)
    if route is None:
        return None
    name, content_type = route
    content = files(__package__).joinpath(name).read_bytes()
    return content, content_type


_PAYLOAD_LOCK = threading.Lock()
_CACHED_PAYLOADS: dict[tuple[str, str, str], dict[str, object]] = {}


def _selected_option(value: str | None, allowed: Sequence[str], default: str) -> str:
    if value in allowed:
        return value
    return default


def _request_options(path: str, body: bytes = b"") -> tuple[str, str]:
    """Parse dashboard run options from a query string or JSON request body."""
    from ...attackers.scripted import FIXTURE_IDS

    parsed = urlsplit(path)
    query = parse_qs(parsed.query)
    data: dict[str, object] = {}
    if body:
        try:
            decoded = json.loads(body.decode())
        except (UnicodeDecodeError, json.JSONDecodeError):
            decoded = {}
        if isinstance(decoded, dict):
            data = decoded

    env_id = str(data.get("env_id") or query.get("env_id", [""])[0] or DEFAULT_ENV_ID)
    grading = str(data.get("grading") or query.get("grading", [""])[0] or DEFAULT_GRADING)
    return (
        _selected_option(env_id, FIXTURE_IDS, DEFAULT_ENV_ID),
        _selected_option(grading, ("inband", "oob"), DEFAULT_GRADING),
    )


def _dashboard_backend() -> str:
    """Which sandbox backend the dashboard runs the product pipeline on.

    Defaults to a *real* backend: the fake sandbox does not execute code, so it silently
    misreports the hardcode (E2) and mock-dependency (E5) classes as missed and the
    recall as 6/8 instead of the true 8/8. Set ``RLINT_DASHBOARD_BACKEND=fake`` for a
    Docker/key-free preview when you knowingly want the placeholder numbers.

    Deliberately does *not* consult ``RLINT_SANDBOX``: that is commonly pinned to ``fake``
    in a developer ``.env`` for fast unit runs, and the dashboard must still show real
    recall regardless. Only the dashboard-specific override switches it.
    """
    return os.environ.get("RLINT_DASHBOARD_BACKEND") or "local"


def _run_pipeline(backend: str, env_id: str, grading: str) -> dict[str, object]:
    from ...attackers.scripted import FIXTURE_IDS, load_fixture_spec, registered_attackers
    from ...harness import run_suite
    from ..registry import build_report

    env_id = _selected_option(env_id, FIXTURE_IDS, DEFAULT_ENV_ID)
    grading = _selected_option(grading, ("inband", "oob"), DEFAULT_GRADING)
    spec = load_fixture_spec(env_id)
    attackers = registered_attackers()
    suite = run_suite(
        spec,
        attackers,
        backend=backend,
        grading=grading,
        max_parallel=len(attackers),
    )
    payload = report_payload(
        build_report(suite.env_id, suite.rollouts, solution_paths=spec.solution_paths)
    )
    active_recall = payload.get("envs", [{}])[0].get("recall", "—")
    payload["envs"] = [
        {
            "id": fixture_id,
            "name": fixture_id,
            "recall": active_recall if fixture_id == env_id else "—",
            "status": "this run" if fixture_id == env_id else "ready",
        }
        for fixture_id in FIXTURE_IDS
    ]
    payload["runtime"] = {
        "backend": suite.backend,
        "grading": suite.grading,
        "selected_env": spec.env_id,
        "available_envs": list(FIXTURE_IDS),
        "wall_time_s": suite.wall_time_s,
        "serial_time_s": suite.serial_time_s,
        "max_parallel": suite.max_parallel,
        "sandboxes_created": suite.sandboxes_created,
    }
    payload["wallclock"] = [
        {
            "label": f"{suite.max_parallel} concurrent",
            "v": max(1, round(suite.wall_time_s)),
            "ok": True,
        },
        {
            "label": "serial equivalent",
            "v": max(1, round(suite.serial_time_s)),
            "ok": False,
        },
    ]
    return payload


def product_payload(
    env_id: str = DEFAULT_ENV_ID,
    grading: str = DEFAULT_GRADING,
    *,
    force: bool = False,
) -> dict[str, object]:
    """Run (and cache) the full product pipeline for the dashboard views.

    Cached because the real backend spins up two sandboxes per attacker per call, which
    must not happen on every page load. ``force=True`` (the ``/api/run`` button) re-runs.
    If the real backend is unavailable (e.g. no Docker), fall back to the fake sandbox so
    the dashboard still serves, and tag the runtime so the UI can say the numbers are
    placeholders rather than silently showing 6/8.
    """
    with _PAYLOAD_LOCK:
        backend = _dashboard_backend()
        key = (backend, env_id, grading)
        if key in _CACHED_PAYLOADS and not force:
            return _CACHED_PAYLOADS[key]
        try:
            payload = _run_pipeline(backend, env_id, grading)
        except Exception as exc:  # noqa: BLE001 - degrade to fake rather than 500 the page
            if backend == "fake":
                raise
            payload = _run_pipeline("fake", env_id, grading)
            runtime = payload.setdefault("runtime", {})
            if isinstance(runtime, dict):
                runtime["backend_fallback"] = f"{backend} unavailable ({exc}); showing fake numbers"
        _CACHED_PAYLOADS[key] = payload
        return payload


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
            env_id, grading = _request_options(self.path)
            self._send_json(product_payload(env_id, grading))
            return
        self._send_asset(include_body=True)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if urlsplit(self.path).path == "/api/run":
            content_length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(content_length) if content_length else b""
            env_id, grading = _request_options(self.path, body)
            self._send_json(product_payload(env_id, grading, force=True))
            return
        self._send_not_found(include_body=True)

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if urlsplit(self.path).path == "/api/report":
            env_id, grading = _request_options(self.path)
            self._send_json(product_payload(env_id, grading), include_body=False)
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
