"""Control-plane tests: login, session cookies, token auth and the daemon <-> dashboard relay."""
import time

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import server

TOKEN = "t" * 32
PASSWORD = "correct horse battery staple"


def make_client(**kw):
    settings = server.Settings(**kw)
    return TestClient(server.create_app(settings), follow_redirects=False)


def daemon_headers(token=TOKEN):
    return {"Authorization": f"Bearer {token}"}


def assert_rejected(client, url, **kw):
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(url, **kw):
            pass
    assert exc.value.code == 1008


# ------------------------------------------------------------------ sessions


def test_session_roundtrip_tamper_and_expiry():
    secret = b"k" * 32
    value = server.make_session(secret, 60)
    assert server.session_valid(secret, value)
    assert not server.session_valid(b"x" * 32, value)
    assert not server.session_valid(secret, value[:-2] + "00")
    assert not server.session_valid(secret, "")
    assert not server.session_valid(secret, None)
    assert not server.session_valid(secret, "garbage")
    expired = server.make_session(secret, 60, now=time.time() - 3600)
    assert not server.session_valid(secret, expired)


def test_login_limiter_blocks_and_resets():
    lim = server.LoginLimiter(max_failures=2, window=60)
    assert not lim.blocked("a")
    lim.record_failure("a")
    lim.record_failure("a")
    assert lim.blocked("a") and not lim.blocked("b")
    lim.reset("a")
    assert not lim.blocked("a")


# ------------------------------------------------------------------ dashboard login


def test_dashboard_requires_login_when_password_set():
    c = make_client(dashboard_password=PASSWORD)
    r = c.get("/")
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert c.get("/login").status_code == 200
    assert c.get("/api/session").json() == {"auth_required": True, "authenticated": False}


def test_wrong_password_then_right_password():
    c = make_client(dashboard_password=PASSWORD)
    bad = c.post("/login", data={"password": "nope"})
    assert bad.status_code == 303 and bad.headers["location"] == "/login?error=1"
    assert "set-cookie" not in bad.headers

    good = c.post("/login", data={"password": PASSWORD})
    assert good.status_code == 303 and good.headers["location"] == "/"
    cookie = good.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie

    page = c.get("/")
    assert page.status_code == 200 and "AEGIS" in page.text
    assert "default-src 'self'" in page.headers["content-security-policy"]
    assert page.headers["x-frame-options"] == "DENY"
    assert page.headers["referrer-policy"] == "same-origin"  # "no-referrer" breaks same-origin login posts in browsers
    assert c.get("/api/session").json()["authenticated"] is True

    c.post("/logout")
    assert c.get("/").status_code == 303


def test_login_is_rate_limited():
    c = make_client(dashboard_password=PASSWORD)
    for _ in range(server.LOGIN_MAX_FAILURES):
        assert c.post("/login", data={"password": "x"}).status_code == 303
    assert c.post("/login", data={"password": PASSWORD}).status_code == 429


def test_login_rejects_foreign_origin():
    c = make_client(dashboard_password=PASSWORD)
    r = c.post("/login", data={"password": PASSWORD}, headers={"Origin": "http://evil.example"})
    assert r.status_code == 403


def test_local_mode_without_password_needs_no_login():
    c = make_client()
    assert c.get("/").status_code == 200
    assert c.get("/api/session").json() == {"auth_required": False, "authenticated": True}


def test_static_assets_and_health():
    c = make_client()
    assert c.get("/assets/app.js").status_code == 200
    assert c.get("/assets/tailwind.css").status_code == 200
    assert c.get("/healthz").json() == {"ok": True}
    assert c.get("/docs").status_code == 404 and c.get("/openapi.json").status_code == 404


def test_dashboard_websocket_needs_session_cookie():
    c = make_client(dashboard_password=PASSWORD)
    assert_rejected(c, "/ws/dashboard")
    c.post("/login", data={"password": PASSWORD})
    with c.websocket_connect("/ws/dashboard") as ws:
        assert ws.receive_json()["type"] == "status"


def test_websocket_rejects_cross_site_origin():
    c = make_client()
    assert_rejected(c, "/ws/dashboard", headers={"Origin": "http://evil.example"})
    with c.websocket_connect("/ws/dashboard", headers={"Origin": "http://testserver"}) as ws:
        assert ws.receive_json()["type"] == "status"


# ------------------------------------------------------------------ daemon auth


def test_daemon_needs_token_in_header():
    c = make_client(token=TOKEN)
    assert_rejected(c, "/ws/security-stream?host=h1")
    assert_rejected(c, "/ws/security-stream?host=h1", headers=daemon_headers("wrong"))
    # a token in the query string is deliberately ignored
    assert_rejected(c, f"/ws/security-stream?host=h1&token={TOKEN}")
    with c.websocket_connect("/ws/security-stream?host=h1", headers=daemon_headers()):
        pass
    with c.websocket_connect("/ws/security-stream?host=h1", headers={"X-AEGIS-Token": TOKEN}):
        pass


# ------------------------------------------------------------------ relay


def test_telemetry_command_and_ack_relay():
    c = make_client(token=TOKEN)
    with c.websocket_connect("/ws/dashboard") as dash:
        assert dash.receive_json()["hosts"] == []
        with c.websocket_connect("/ws/security-stream?host=h1", headers=daemon_headers()) as daemon:
            assert dash.receive_json()["hosts"] == ["h1"]

            daemon.send_json({"type": "telemetry", "processes": [{"pid": 42, "name": "python"}], "host": "spoofed"})
            seen = dash.receive_json()
            assert seen["type"] == "telemetry" and seen["host"] == "h1"  # host comes from the connection, not the payload

            dash.send_json({"action": "kill", "pid": 42, "host": "h1", "create_time": 12.5})
            control = daemon.receive_json()
            assert control["type"] == "control" and control["action"] == "KILL"
            assert control["pid"] == 42 and control["create_time"] == 12.5
            result = dash.receive_json()
            assert result["type"] == "command_result" and result["ok"] and result["pending"]

            daemon.send_json({"type": "ack", "ok": True, "pid": 42, "action": "KILL", "detail": "terminated"})
            ack = dash.receive_json()
            assert ack["type"] == "ack" and ack["host"] == "h1"
        assert dash.receive_json() == {"type": "host_offline", "host": "h1"}
        assert dash.receive_json()["hosts"] == []


@pytest.mark.parametrize("message,fragment", [
    ({"action": "FORMAT", "pid": 5}, "Unsupported action"),
    ({"action": "KILL", "pid": "5"}, "positive integer"),
    ({"action": "KILL", "pid": True}, "positive integer"),
    ({"action": "KILL", "pid": -1}, "positive integer"),
    ({"action": "KILL", "pid": 5, "host": "ghost"}, "offline"),
])
def test_invalid_commands_never_reach_a_daemon(message, fragment):
    c = make_client()
    with c.websocket_connect("/ws/dashboard") as dash:
        dash.receive_json()
        dash.send_json(message)
        result = dash.receive_json()
        assert result["ok"] is False and fragment in result["detail"]


def test_new_dashboard_gets_last_telemetry_snapshot():
    c = make_client()
    with c.websocket_connect("/ws/security-stream?host=h9") as daemon:
        daemon.send_json({"type": "telemetry", "processes": []})
        time.sleep(0.1)
        with c.websocket_connect("/ws/dashboard") as dash:
            assert dash.receive_json()["type"] == "status"
            assert dash.receive_json()["type"] == "telemetry"


def test_replaced_daemon_does_not_mark_host_offline():
    c = make_client()
    with c.websocket_connect("/ws/dashboard") as dash:
        dash.receive_json()
        with c.websocket_connect("/ws/security-stream?host=h1"):
            dash.receive_json()
            with c.websocket_connect("/ws/security-stream?host=h1"):
                msgs = []
                while True:
                    m = dash.receive_json()
                    msgs.append(m)
                    if m["type"] == "status" and m["hosts"] == ["h1"] and len(msgs) >= 1:
                        break
                assert all(m["type"] != "host_offline" for m in msgs)


# ------------------------------------------------------------------ startup policy


def test_startup_check(monkeypatch):
    monkeypatch.delenv("AEGIS_ALLOW_INSECURE", raising=False)
    server.startup_check("127.0.0.1", server.Settings())
    with pytest.raises(SystemExit, match="AEGIS_TOKEN"):
        server.startup_check("0.0.0.0", server.Settings(dashboard_password=PASSWORD))
    with pytest.raises(SystemExit, match="AEGIS_DASHBOARD_PASSWORD"):
        server.startup_check("0.0.0.0", server.Settings(token=TOKEN))
    server.startup_check("0.0.0.0", server.Settings(token=TOKEN, dashboard_password=PASSWORD))
    monkeypatch.setenv("AEGIS_ALLOW_INSECURE", "1")
    server.startup_check("0.0.0.0", server.Settings())
