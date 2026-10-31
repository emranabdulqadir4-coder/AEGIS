#!/usr/bin/env python3
"""AEGIS control plane.

Serves the dashboard, receives telemetry from host daemons (daemon_security.py) and
relays operator containment commands (SUSPEND / RESUME / KILL) to the right daemon.

Run locally:  python server.py
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import uvicorn
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

BASE_DIR = Path(__file__).resolve().parent
WEB_DIR = BASE_DIR / "web"

MAX_MESSAGE_BYTES = 256 * 1024
HOST_PATTERN = re.compile(r"[^A-Za-z0-9._-]")
LOCAL_HOSTS = {"127.0.0.1", "::1", "localhost"}
SESSION_COOKIE = "aegis_session"
LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW_SECONDS = 300
LOG = logging.getLogger("aegis.server")

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'none'; "
        "base-uri 'none'; form-action 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    # NOT "no-referrer": that makes browsers send "Origin: null" on same-origin form posts, which the login CSRF check rejects.
    "Referrer-Policy": "same-origin",
    "Cache-Control": "no-store",
}


def load_local_env(path: Path | None = None) -> None:
    """Load a small KEY=VALUE .env file without overriding real environment variables."""
    try:
        lines = (path or BASE_DIR / ".env").read_text(encoding="utf-8-sig").splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip('"').strip("'")
        if key.strip() and value:
            os.environ.setdefault(key.strip(), value)


@dataclass
class Settings:
    token: str = ""                      # shared secret host daemons must present
    dashboard_password: str = ""         # operator login; empty = no login (localhost dev only)
    allowed_origins: frozenset[str] = frozenset()
    session_ttl: int = 12 * 3600
    session_secret: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    secure_cookie: bool = False          # set when served over https

    @property
    def auth_required(self) -> bool:
        return bool(self.dashboard_password)

    @classmethod
    def from_env(cls) -> "Settings":
        env = os.environ
        origins = frozenset(
            item.strip().lower().rstrip("/")
            for item in env.get("AEGIS_ALLOWED_ORIGINS", "").split(",")
            if item.strip()
        )
        secret = env.get("AEGIS_SESSION_SECRET", "").strip()
        return cls(
            token=env.get("AEGIS_TOKEN", "").strip(),
            dashboard_password=env.get("AEGIS_DASHBOARD_PASSWORD", "").strip(),
            allowed_origins=origins,
            session_secret=secret.encode() if secret else secrets.token_bytes(32),
            secure_cookie=env.get("AEGIS_SECURE_COOKIE", "0") == "1",
        )


# ---------------------------------------------------------------------- sessions


def make_session(secret: bytes, ttl: int, now: float | None = None) -> str:
    expires = int((now or time.time()) + ttl)
    body = f"{expires}.{secrets.token_hex(8)}"
    sig = hmac.new(secret, body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def session_valid(secret: bytes, value: str | None, now: float | None = None) -> bool:
    if not value:
        return False
    body, _, sig = value.rpartition(".")
    expected = hmac.new(secret, body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig.encode(), expected.encode()):
        return False
    try:
        expires = int(body.split(".", 1)[0])
    except ValueError:
        return False
    return expires > (now or time.time())


class LoginLimiter:
    """Blocks an address after too many failed logins in a window."""

    def __init__(self, max_failures: int = LOGIN_MAX_FAILURES, window: int = LOGIN_WINDOW_SECONDS) -> None:
        self.max_failures = max_failures
        self.window = window
        self.failures: dict[str, list[float]] = {}

    def _recent(self, key: str) -> list[float]:
        cutoff = time.monotonic() - self.window
        recent = [t for t in self.failures.get(key, []) if t > cutoff]
        if recent:
            self.failures[key] = recent
        else:
            self.failures.pop(key, None)
        return recent

    def blocked(self, key: str) -> bool:
        return len(self._recent(key)) >= self.max_failures

    def record_failure(self, key: str) -> None:
        self._recent(key)
        self.failures.setdefault(key, []).append(time.monotonic())

    def reset(self, key: str) -> None:
        self.failures.pop(key, None)


# ---------------------------------------------------------------------- helpers


def _decode(raw: str) -> dict[str, Any] | None:
    if len(raw.encode("utf-8")) > MAX_MESSAGE_BYTES:
        return None
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _origin_ok(origin: str | None, host_header: str, allowed: frozenset[str]) -> bool:
    if not origin:
        return True  # native clients (the daemon) do not send Origin
    normalized = origin.lower().rstrip("/")
    return normalized in allowed or urlparse(normalized).netloc == host_header.lower()


def _bearer_token(headers: Any) -> str:
    auth = headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return headers.get("x-aegis-token", "").strip()


class ControlPlane:
    def __init__(self) -> None:
        self.daemons: dict[str, WebSocket] = {}
        self.dashboard_clients: set[WebSocket] = set()
        self.last_telemetry: dict[str, dict[str, Any]] = {}
        self.lock = asyncio.Lock()

    async def send(self, ws: WebSocket, payload: dict[str, Any]) -> bool:
        try:
            await asyncio.wait_for(ws.send_text(json.dumps(payload, separators=(",", ":"))), 5)
            return True
        except Exception:
            return False

    async def broadcast(self, payload: dict[str, Any]) -> None:
        async with self.lock:
            clients = list(self.dashboard_clients)
        failed = [ws for ws in clients if not await self.send(ws, payload)]
        if failed:
            async with self.lock:
                for ws in failed:
                    self.dashboard_clients.discard(ws)

    def status_payload(self) -> dict[str, Any]:
        return {
            "type": "status",
            "security_daemons": len(self.daemons),
            "dashboards": len(self.dashboard_clients),
            "hosts": sorted(self.daemons),
            "ts": time.time(),
        }

    async def status(self) -> None:
        await self.broadcast(self.status_payload())

    async def command(self, dashboard: WebSocket, msg: dict[str, Any]) -> None:
        action = str(msg.get("action", "")).upper()
        if action not in {"SUSPEND", "RESUME", "KILL"}:
            await self.send(dashboard, {"type": "command_result", "ok": False, "detail": "Unsupported action"})
            return
        pid = msg.get("pid")
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            await self.send(dashboard, {"type": "command_result", "ok": False, "detail": "PID must be a positive integer"})
            return

        host = str(msg.get("host", ""))[:64]
        if not host and len(self.daemons) == 1:
            host = next(iter(self.daemons))
        daemon = self.daemons.get(host)
        if daemon is None:
            detail = (
                "Choose a host when multiple daemons are connected"
                if len(self.daemons) > 1 and not host
                else "Target daemon is offline"
            )
            await self.send(dashboard, {"type": "command_result", "ok": False, "detail": detail, "pid": pid})
            return

        command_id = str(msg.get("command_id") or uuid.uuid4().hex)[:64]
        payload: dict[str, Any] = {"type": "control", "action": action, "pid": pid, "command_id": command_id}
        created = msg.get("create_time")
        if isinstance(created, (int, float)) and not isinstance(created, bool):
            payload["create_time"] = float(created)
        LOG.info("AUDIT command %s pid=%s host=%s id=%s", action, pid, host, command_id)
        if not await self.send(daemon, payload):
            await self.send(dashboard, {"type": "command_result", "ok": False, "detail": "Daemon connection failed", "pid": pid})
            return
        await self.send(dashboard, {
            "type": "command_result", "ok": True, "pending": True,
            "detail": f"{action} command delivered to {host}; waiting for daemon confirmation",
            "pid": pid, "host": host, "action": action, "command_id": command_id,
        })


# ---------------------------------------------------------------------- app factory


def create_app(settings: Settings | None = None) -> FastAPI:
    cfg = settings or Settings.from_env()
    plane = ControlPlane()
    limiter = LoginLimiter()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        logging.basicConfig(level=os.environ.get("AEGIS_LOG_LEVEL", "INFO").upper())
        yield

    app = FastAPI(title="AEGIS Control Plane", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.plane = plane
    app.state.settings = cfg
    app.mount("/assets", StaticFiles(directory=WEB_DIR / "assets"), name="assets")

    def authenticated(cookies: Any) -> bool:
        return (not cfg.auth_required) or session_valid(cfg.session_secret, cookies.get(SESSION_COOKIE))

    def page(name: str) -> FileResponse:
        return FileResponse(WEB_DIR / name, media_type="text/html", headers=SECURITY_HEADERS)

    @app.get("/")
    async def dashboard(request: Request):
        if not authenticated(request.cookies):
            return RedirectResponse("/login", status_code=303)
        return page("dashboard.html")

    @app.get("/login")
    async def login_page(request: Request):
        if authenticated(request.cookies):
            return RedirectResponse("/", status_code=303)
        return page("login.html")

    @app.post("/login")
    async def login(request: Request):
        if not cfg.auth_required:
            return RedirectResponse("/", status_code=303)
        if not _origin_ok(request.headers.get("origin"), request.headers.get("host", ""), cfg.allowed_origins):
            return JSONResponse({"detail": "bad origin"}, status_code=403)
        client = request.client.host if request.client else "unknown"
        if limiter.blocked(client):
            return JSONResponse({"detail": "Too many attempts. Try again later."}, status_code=429)
        body = parse_qs((await request.body())[:4096].decode("utf-8", "replace"))
        supplied = (body.get("password") or [""])[0]
        if not hmac.compare_digest(supplied.encode(), cfg.dashboard_password.encode()):
            limiter.record_failure(client)
            LOG.warning("AUDIT failed dashboard login from %s", client)
            return RedirectResponse("/login?error=1", status_code=303)
        limiter.reset(client)
        LOG.info("AUDIT dashboard login from %s", client)
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(
            SESSION_COOKIE, make_session(cfg.session_secret, cfg.session_ttl),
            max_age=cfg.session_ttl, httponly=True, samesite="strict", secure=cfg.secure_cookie, path="/",
        )
        return response

    @app.post("/logout")
    async def logout():
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(SESSION_COOKIE, path="/")
        return response

    @app.get("/api/session")
    async def session_info(request: Request) -> JSONResponse:
        return JSONResponse(
            {"auth_required": cfg.auth_required, "authenticated": authenticated(request.cookies)},
            headers=SECURITY_HEADERS,
        )

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        return JSONResponse({"ok": True})

    @app.websocket("/ws/security-stream")
    async def security_stream(ws: WebSocket) -> None:
        origin_ok = _origin_ok(ws.headers.get("origin"), ws.headers.get("host", ""), cfg.allowed_origins)
        token_ok = (not cfg.token) or hmac.compare_digest(_bearer_token(ws.headers).encode(), cfg.token.encode())
        if not (origin_ok and token_ok):
            await ws.close(code=1008)
            return
        await ws.accept()
        host = HOST_PATTERN.sub("", ws.query_params.get("host", ""))[:64] or f"host-{uuid.uuid4().hex[:8]}"
        previous = plane.daemons.get(host)
        plane.daemons[host] = ws
        if previous is not None and previous is not ws:
            try:
                await previous.close(code=1001)
            except Exception:
                pass
        LOG.info("security daemon connected: %s", host)
        await plane.status()
        try:
            async for raw in ws.iter_text():
                msg = _decode(raw)
                if msg is None:
                    continue
                kind = msg.get("type")
                if kind == "telemetry":
                    msg["host"] = host
                    msg["received_at"] = time.time()
                    plane.last_telemetry[host] = msg
                    await plane.broadcast(msg)
                elif kind == "ack":
                    msg["host"] = host
                    LOG.info("AUDIT ack %s pid=%s host=%s ok=%s", msg.get("action"), msg.get("pid"), host, msg.get("ok"))
                    await plane.broadcast(msg)
        except WebSocketDisconnect:
            pass
        except Exception:
            LOG.exception("security daemon stream failed for %s", host)
        finally:
            if plane.daemons.get(host) is ws:
                plane.daemons.pop(host, None)
                plane.last_telemetry.pop(host, None)
                await plane.broadcast({"type": "host_offline", "host": host})
            await plane.status()
            LOG.info("security daemon disconnected: %s", host)

    @app.websocket("/ws/dashboard")
    async def dashboard_stream(ws: WebSocket) -> None:
        origin_ok = _origin_ok(ws.headers.get("origin"), ws.headers.get("host", ""), cfg.allowed_origins)
        if not origin_ok or not authenticated(ws.cookies):
            await ws.close(code=1008)
            return
        await ws.accept()
        plane.dashboard_clients.add(ws)
        await plane.send(ws, plane.status_payload())
        for snapshot in list(plane.last_telemetry.values()):
            await plane.send(ws, snapshot)
        try:
            async for raw in ws.iter_text():
                msg = _decode(raw)
                if msg is not None:
                    await plane.command(ws, msg)
        except WebSocketDisconnect:
            pass
        except Exception:
            LOG.exception("dashboard websocket failed")
        finally:
            plane.dashboard_clients.discard(ws)
            await plane.status()

    return app


def startup_check(host: str, cfg: Settings) -> None:
    """The control plane can terminate host processes: never expose it unprotected."""
    if host in LOCAL_HOSTS or os.environ.get("AEGIS_ALLOW_INSECURE") == "1":
        return
    if not cfg.token:
        raise SystemExit("Refusing non-local bind without AEGIS_TOKEN. Set a long random token or bind to 127.0.0.1.")
    if not cfg.dashboard_password:
        raise SystemExit("Refusing non-local bind without AEGIS_DASHBOARD_PASSWORD. Set one or bind to 127.0.0.1.")


load_local_env()
app = create_app()

if __name__ == "__main__":
    bind_host = os.environ.get("AEGIS_HOST", "127.0.0.1")
    startup_check(bind_host, app.state.settings)
    uvicorn.run(app, host=bind_host, port=int(os.environ.get("AEGIS_PORT", "8000")), ws_max_size=MAX_MESSAGE_BYTES)
