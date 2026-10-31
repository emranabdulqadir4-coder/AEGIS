"""Safety-rail tests for the host daemon. These start real (harmless) child processes."""
import logging
import os
import subprocess
import sys
import time

import psutil
import pytest

import daemon_security as d

posix_only = pytest.mark.skipif(os.name == "nt", reason="uses POSIX tools / signals")


@pytest.fixture
def scanner():
    return d.ProcessScanner(rogue_cpu=90.0, rogue_rss_mb=4096.0, rogue_scans=3)


@pytest.fixture
def controller(scanner):
    return d.ContainmentController(scanner)


@pytest.fixture
def child():
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    time.sleep(0.3)
    yield proc
    if proc.poll() is None:
        proc.kill()
    proc.wait(timeout=5)


def cmd(action, pid, **extra):
    return {"action": action, "pid": pid, "command_id": "t1", **extra}


# ------------------------------------------------------------------ watch list / protection


def test_default_watch_list(scanner):
    assert scanner.name_is_watched("python3.13")
    assert scanner.name_is_watched("Node.exe")
    assert scanner.name_is_watched("ollama")
    assert not scanner.name_is_watched("sshd")


def test_custom_watch_list():
    s = d.ProcessScanner(90, 4096, 3, watch_tokens=("java", " Ruby "))
    assert s.name_is_watched("java") and s.name_is_watched("ruby")
    assert not s.name_is_watched("python")


def test_empty_custom_watch_list_falls_back_to_default():
    s = d.ProcessScanner(90, 4096, 3, watch_tokens=("", " "))
    assert s.watch_tokens == d.DEFAULT_WATCH_TOKENS


def test_protected_pids_and_scripts(scanner):
    assert scanner.is_protected(os.getpid(), [])
    assert scanner.is_protected(1, [])
    assert scanner.is_protected(999999, ["python", "/srv/aegis/server.py"])
    assert scanner.is_protected(999999, ["python", "daemon_security.py"])
    assert not scanner.is_protected(999999, ["python", "my_agent.py"])


# ------------------------------------------------------------------ refusals


@pytest.mark.parametrize("bad_pid", [0, -5, True, "12", None, 1.5])
def test_invalid_pid_is_rejected(controller, bad_pid):
    ack = controller.execute(cmd("KILL", bad_pid))
    assert not ack["ok"] and "invalid pid" in ack["detail"]


def test_unsupported_action_is_rejected(controller, child):
    ack = controller.execute(cmd("REBOOT", child.pid))
    assert not ack["ok"] and "unsupported" in ack["detail"]
    assert child.poll() is None


def test_refuses_own_process(controller):
    ack = controller.execute(cmd("KILL", os.getpid()))
    assert not ack["ok"] and "protected" in ack["detail"]


@posix_only
def test_refuses_process_outside_watch_list(controller):
    other = subprocess.Popen(["sleep", "60"])
    try:
        time.sleep(0.2)
        ack = controller.execute(cmd("KILL", other.pid))
        assert not ack["ok"] and "outside the watch list" in ack["detail"]
        assert other.poll() is None
    finally:
        other.kill()
        other.wait(timeout=5)


def test_refuses_recycled_pid(controller, child):
    wrong = psutil.Process(child.pid).create_time() - 100
    ack = controller.execute(cmd("KILL", child.pid, create_time=wrong))
    assert not ack["ok"] and "recycled" in ack["detail"]
    assert child.poll() is None


def test_missing_process(controller):
    ack = controller.execute(cmd("KILL", 4_000_000))
    assert not ack["ok"] and "no longer exists" in ack["detail"]


# ------------------------------------------------------------------ actions


@posix_only
def test_suspend_resume_roundtrip(controller, scanner, child):
    created = psutil.Process(child.pid).create_time()
    ack = controller.execute(cmd("SUSPEND", child.pid, create_time=created))
    assert ack["ok"], ack
    time.sleep(0.2)
    assert psutil.Process(child.pid).status() == psutil.STATUS_STOPPED
    row = next(r for r in scanner.scan() if r["pid"] == child.pid)
    assert row["status"] == "suspended"

    ack = controller.execute(cmd("RESUME", child.pid, create_time=created))
    assert ack["ok"], ack
    time.sleep(0.2)
    assert psutil.Process(child.pid).status() != psutil.STATUS_STOPPED


def test_kill_terminates_process_tree(controller):
    parent = subprocess.Popen([
        sys.executable, "-c",
        "import subprocess, sys, time; subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)']); time.sleep(120)",
    ])
    try:
        time.sleep(0.6)
        kids = psutil.Process(parent.pid).children(recursive=True)
        assert kids, "test setup: parent should have a child"
        ack = controller.execute(cmd("KILL", parent.pid, create_time=psutil.Process(parent.pid).create_time()))
        assert ack["ok"], ack
        assert "1 descendant" in ack["detail"]
        parent.wait(timeout=5)
        assert not any(k.is_running() and k.status() != psutil.STATUS_ZOMBIE for k in kids)
    finally:
        if parent.poll() is None:
            parent.kill()


def test_scan_reports_expected_fields(scanner, child):
    row = next(r for r in scanner.scan() if r["pid"] == child.pid)
    assert {"pid", "ppid", "name", "cpu", "rss_mb", "status", "create_time", "cmd", "protected"} <= row.keys()
    assert row["status"] == "normal" and row["protected"] is False


# ------------------------------------------------------------------ connection helpers


def test_token_is_never_placed_in_the_url():
    url = d.build_url("ws://example.test/ws/security-stream", "my host/1")
    assert "token" not in url and "host=my%20host%2F1" in url
    assert d.auth_headers("s3cret") == {"Authorization": "Bearer s3cret"}
    assert d.auth_headers("") == {}


def test_resolve_connection_precedence():
    gw, tok = d.resolve_connection(None, {"AEGIS_GATEWAY": "wss://g/x", "AEGIS_TOKEN": "shared", "AEGIS_API_KEY": "key"})
    assert (gw, tok) == ("wss://g/x", "shared")
    gw, tok = d.resolve_connection("ws://cli", {"AEGIS_API_KEY": "key"})
    assert (gw, tok) == ("ws://cli", "key")
    assert d.resolve_connection(None, {})[0] == d.DEFAULT_GATEWAY


def test_cleartext_warning(caplog):
    with caplog.at_level(logging.WARNING, logger="aegis.security"):
        d.warn_if_cleartext("ws://localhost:8000/x", "tok")
        d.warn_if_cleartext("wss://remote.example/x", "tok")
        assert not caplog.records
        d.warn_if_cleartext("ws://remote.example/x", "tok")
        assert "unencrypted" in caplog.text
