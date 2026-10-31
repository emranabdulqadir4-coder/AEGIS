#!/usr/bin/env python3
"""AEGIS host process containment daemon (Windows, Linux, macOS).

Every 2 seconds it walks the process table, selects processes whose name contains one of
the watch-list fragments (default 'python', 'node', 'ollama'; see --watch), and ships PID / name / CPU % / RSS MB to the gateway.
It also executes SUSPEND, RESUME and KILL commands relayed from the dashboard.

Run with administrative/root privileges to be able to control processes owned by other users:
    sudo python3 daemon_security.py
    (Windows, elevated prompt)  python daemon_security.py

Safety rails (a containment tool must not be a foot-gun):
  * only processes whose name matches the watch list can be controlled
  * the daemon, its ancestors and the AEGIS gateway/engine scripts are protected
  * if the dashboard supplies a create_time it must match, so a recycled PID is never hit
"""

from __future__ import annotations

import argparse
import asyncio
import ctypes
import json
import logging
import os
import platform
import signal
import socket
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple
from urllib.parse import quote, urlparse

import psutil
import websockets

LOG = logging.getLogger("aegis.security")

IS_WINDOWS = platform.system() == "Windows"
SCAN_INTERVAL_SECONDS = 2.0
DEFAULT_WATCH_TOKENS = ("python", "node", "ollama")
WATCH_TOKENS = DEFAULT_WATCH_TOKENS  # kept for backwards compatibility
PROTECTED_SCRIPT_NAMES = {"server.py", "daemon_security.py", "daemon_purchase.py", "server:app"}
CREATE_TIME_TOLERANCE_SECONDS = 1.0
TREE_KILL_GRACE_SECONDS = 3.0


def is_privileged() -> bool:
    try:
        if IS_WINDOWS:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        return os.geteuid() == 0
    except Exception:
        return False


# ---------------------------------------------------------------------- suspend / resume


class ProcessFreezer:
    """Cross-platform pause/resume abstraction.

    Windows: NtSuspendProcess / NtResumeProcess from ntdll (suspends every thread atomically).
    POSIX:   SIGSTOP / SIGCONT.
    """

    PROCESS_SUSPEND_RESUME = 0x0800

    def __init__(self) -> None:
        self._kernel32 = None
        self._ntdll = None
        if IS_WINDOWS:
            from ctypes import wintypes

            self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
            self._ntdll = ctypes.WinDLL("ntdll")  # type: ignore[attr-defined]
            self._kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            self._kernel32.OpenProcess.restype = wintypes.HANDLE
            self._kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            self._kernel32.CloseHandle.restype = wintypes.BOOL
            self._ntdll.NtSuspendProcess.argtypes = [wintypes.HANDLE]
            self._ntdll.NtSuspendProcess.restype = ctypes.c_long
            self._ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
            self._ntdll.NtResumeProcess.restype = ctypes.c_long

    def suspend(self, pid: int) -> None:
        if IS_WINDOWS:
            self._nt_call(self._ntdll.NtSuspendProcess, pid)  # type: ignore[union-attr]
        else:
            os.kill(pid, signal.SIGSTOP)

    def resume(self, pid: int) -> None:
        if IS_WINDOWS:
            self._nt_call(self._ntdll.NtResumeProcess, pid)  # type: ignore[union-attr]
        else:
            os.kill(pid, signal.SIGCONT)

    def _nt_call(self, function: Any, pid: int) -> None:
        handle = self._kernel32.OpenProcess(self.PROCESS_SUSPEND_RESUME, False, pid)  # type: ignore[union-attr]
        if not handle:
            raise psutil.AccessDenied(pid)
        try:
            status = function(handle)
            if status != 0:
                raise OSError(f"NTSTATUS 0x{status & 0xFFFFFFFF:08X}")
        finally:
            self._kernel32.CloseHandle(handle)  # type: ignore[union-attr]


# ---------------------------------------------------------------------- scanning


class ProcessScanner:
    def __init__(
        self,
        rogue_cpu: float,
        rogue_rss_mb: float,
        rogue_scans: int,
        watch_tokens: Tuple[str, ...] = DEFAULT_WATCH_TOKENS,
    ) -> None:
        self.watch_tokens = tuple(t.strip().lower() for t in watch_tokens if t.strip()) or DEFAULT_WATCH_TOKENS
        self.rogue_cpu = rogue_cpu
        self.rogue_rss_mb = rogue_rss_mb
        self.rogue_scans = rogue_scans
        self.cpu_streaks: Dict[int, int] = {}
        self.frozen: Set[int] = set()
        self.own_pid = os.getpid()
        self.protected_pids = self._own_lineage()

    def _own_lineage(self) -> Set[int]:
        lineage = {self.own_pid}
        try:
            for ancestor in psutil.Process(self.own_pid).parents():
                lineage.add(ancestor.pid)
        except psutil.Error:
            pass
        return lineage

    def name_is_watched(self, name: str) -> bool:
        lowered = name.lower()
        return any(token in lowered for token in self.watch_tokens)

    def is_protected(self, pid: int, cmdline: List[str]) -> bool:
        if pid <= 1 or pid in self.protected_pids:
            return True
        for arg in cmdline:
            if os.path.basename(arg) in PROTECTED_SCRIPT_NAMES or arg in PROTECTED_SCRIPT_NAMES:
                return True
        return False

    def scan(self) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        seen: Set[int] = set()

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                name = proc.info.get("name") or ""
                if not self.name_is_watched(name):
                    continue
                with proc.oneshot():
                    cpu = proc.cpu_percent(None)
                    rss_mb = proc.memory_info().rss / (1024 * 1024)
                    state = proc.status()
                    created = proc.create_time()
                    ppid = proc.ppid()
                    try:
                        cmdline = proc.cmdline()
                    except (psutil.AccessDenied, psutil.ZombieProcess):
                        cmdline = []
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

            pid = proc.pid
            seen.add(pid)

            if cpu >= self.rogue_cpu:
                self.cpu_streaks[pid] = self.cpu_streaks.get(pid, 0) + 1
            else:
                self.cpu_streaks[pid] = 0

            if state == psutil.STATUS_STOPPED or pid in self.frozen:
                status = "suspended"
            elif self.cpu_streaks[pid] >= self.rogue_scans or rss_mb >= self.rogue_rss_mb:
                status = "rogue"
            else:
                status = "normal"

            rows.append(
                {
                    "pid": pid,
                    "ppid": ppid,
                    "name": name,
                    "cpu": round(cpu, 1),
                    "rss_mb": round(rss_mb, 2),
                    "status": status,
                    "create_time": round(created, 3),
                    "cmd": " ".join(cmdline)[:140],
                    "protected": self.is_protected(pid, cmdline),
                }
            )

        for stale in set(self.cpu_streaks) - seen:
            del self.cpu_streaks[stale]
        self.frozen &= seen
        rows.sort(key=lambda row: row["pid"])
        return rows


# ---------------------------------------------------------------------- execution controls


class ContainmentController:
    def __init__(self, scanner: ProcessScanner) -> None:
        self.scanner = scanner
        self.freezer = ProcessFreezer()

    def execute(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """Blocking; run it in an executor. Always returns an ack dictionary."""
        action = str(command.get("action", "")).upper()
        pid = command.get("pid")
        ack: Dict[str, Any] = {
            "type": "ack",
            "command_id": command.get("command_id", ""),
            "action": action,
            "pid": pid,
            "ok": False,
            "detail": "",
        }
        if action not in {"SUSPEND", "RESUME", "KILL"}:
            ack["detail"] = f"unsupported action '{action}'"
            return ack
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            ack["detail"] = "invalid pid"
            return ack

        try:
            proc = psutil.Process(pid)
            name = proc.name()
            cmdline = self._safe_cmdline(proc)

            if not self.scanner.name_is_watched(name):
                ack["detail"] = f"refused: '{name}' is outside the watch list"
                return ack
            if self.scanner.is_protected(pid, cmdline):
                ack["detail"] = f"refused: PID {pid} is protected (AEGIS component or daemon ancestor)"
                return ack
            expected = command.get("create_time")
            if isinstance(expected, (int, float)) and abs(proc.create_time() - expected) > CREATE_TIME_TOLERANCE_SECONDS:
                ack["detail"] = "refused: PID was recycled by a different process"
                return ack

            if action == "SUSPEND":
                self.freezer.suspend(pid)
                self.scanner.frozen.add(pid)
                ack.update(ok=True, detail=f"suspended {name} ({pid})")
            elif action == "RESUME":
                self.freezer.resume(pid)
                self.scanner.frozen.discard(pid)
                ack.update(ok=True, detail=f"resumed {name} ({pid})")
            else:
                killed = self._kill_tree(proc)
                self.scanner.frozen.discard(pid)
                ack.update(ok=True, detail=f"terminated {name} ({pid}) and {killed} descendant(s)")
        except psutil.NoSuchProcess:
            ack["detail"] = "process no longer exists"
        except psutil.AccessDenied:
            ack["detail"] = "access denied: run the daemon as administrator/root"
        except Exception as exc:
            LOG.exception("control action failed")
            ack["detail"] = f"{exc.__class__.__name__}: {exc}"
        return ack

    @staticmethod
    def _safe_cmdline(proc: psutil.Process) -> List[str]:
        try:
            return proc.cmdline()
        except (psutil.AccessDenied, psutil.ZombieProcess):
            return []

    def _kill_tree(self, root: psutil.Process) -> int:
        """Kill every descendant first (deepest first), then the root. Returns descendants killed."""
        try:
            children = root.children(recursive=True)
        except psutil.NoSuchProcess:
            children = []
        children = [c for c in children if c.pid != self.scanner.own_pid]

        # A stopped process cannot act on SIGTERM; SIGKILL/TerminateProcess works either way.
        for child in reversed(children):
            self._kill_quietly(child)
        _, alive = psutil.wait_procs(children, timeout=TREE_KILL_GRACE_SECONDS)
        for straggler in alive:
            self._kill_quietly(straggler)

        self._kill_quietly(root)
        try:
            root.wait(timeout=TREE_KILL_GRACE_SECONDS)
        except (psutil.NoSuchProcess, psutil.TimeoutExpired):
            pass
        if root.is_running() and root.status() != psutil.STATUS_ZOMBIE:
            raise RuntimeError(f"PID {root.pid} survived SIGKILL")
        return len(children)

    @staticmethod
    def _kill_quietly(proc: psutil.Process) -> None:
        try:
            proc.kill()
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            pass


# ---------------------------------------------------------------------- gateway session


class SecurityDaemon:
    def __init__(
        self, url: str, host_id: str, scanner: ProcessScanner, interval: float, token: str = ""
    ) -> None:
        self.url = url
        self.token = token
        self.host_id = host_id
        self.scanner = scanner
        self.controller = ContainmentController(scanner)
        self.interval = interval
        self.privileged = is_privileged()
        self.cores = psutil.cpu_count(logical=True) or 1

    async def run_forever(self) -> None:
        delay = 1.0
        while True:
            try:
                async with websockets.connect(
                    self.url,
                    additional_headers=auth_headers(self.token),
                    max_size=1 << 20,
                    ping_interval=20,
                    ping_timeout=20,
                ) as ws:
                    LOG.info("connected to gateway as '%s'", self.host_id)
                    delay = 1.0
                    await self._session(ws)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                LOG.warning("gateway link down (%s); retrying in %.0fs", exc.__class__.__name__, delay)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 30.0)

    async def _session(self, ws: Any) -> None:
        tasks = [asyncio.create_task(self._telemetry_loop(ws)), asyncio.create_task(self._control_loop(ws))]
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for finished in done:
                finished.result()  # re-raise the failure that ended the session
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _telemetry_loop(self, ws: Any) -> None:
        loop = asyncio.get_running_loop()
        while True:
            started = time.monotonic()
            rows = await loop.run_in_executor(None, self.scanner.scan)
            payload = {
                "type": "telemetry",
                "host": self.host_id,
                "platform": platform.system(),
                "privileged": self.privileged,
                "cpu_cores": self.cores,
                "ts": time.time(),
                "scan_ms": round((time.monotonic() - started) * 1000, 1),
                "processes": rows,
            }
            await ws.send(json.dumps(payload, separators=(",", ":")))
            await asyncio.sleep(max(0.0, self.interval - (time.monotonic() - started)))

    async def _control_loop(self, ws: Any) -> None:
        loop = asyncio.get_running_loop()
        async for raw in ws:
            try:
                command = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(command, dict) or command.get("type") != "control":
                continue
            LOG.info("control: %s pid=%s", command.get("action"), command.get("pid"))
            ack = await loop.run_in_executor(None, self.controller.execute, command)
            await ws.send(json.dumps(ack, separators=(",", ":")))


def build_url(base: str, host_id: str) -> str:
    """Gateway URL with the host id. The token is sent as a header (see auth_headers), never in the URL."""
    separator = "&" if "?" in base else "?"
    return f"{base}{separator}host={quote(host_id, safe='')}"


def auth_headers(token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {token}"} if token else {}


def warn_if_cleartext(url: str, token: str) -> None:
    parsed = urlparse(url)
    if token and parsed.scheme == "ws" and (parsed.hostname or "") not in ("localhost", "127.0.0.1", "::1"):
        LOG.warning("sending the AEGIS token over unencrypted ws:// to %s; use wss:// behind a TLS proxy", parsed.hostname)


DEFAULT_GATEWAY = "ws://localhost:8000/ws/security-stream"


def resolve_connection(cli_gateway: Optional[str], environ: Optional[Mapping[str, str]] = None) -> Tuple[str, str]:
    """(gateway URL, token) from the command line and environment.

    installer.py writes AEGIS_GATEWAY and AEGIS_API_KEY into agent.env, so the daemon has to read them: the gateway
    is --gateway, else AEGIS_GATEWAY, else the localhost default; the token is AEGIS_TOKEN (shared secret, wins),
    else AEGIS_API_KEY.
    """
    env = os.environ if environ is None else environ
    gateway = cli_gateway or env.get("AEGIS_GATEWAY", "").strip() or DEFAULT_GATEWAY
    token = env.get("AEGIS_TOKEN", "") or env.get("AEGIS_API_KEY", "").strip()
    return gateway, token



def load_local_env() -> None:
    """Load KEY=VALUE from the daemon's adjacent .env without overriding the shell environment."""
    env_path = Path(__file__).resolve().parent / ".env"
    try:
        lines = env_path.read_text(encoding="utf-8-sig").splitlines()
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


def main() -> None:
    load_local_env()
    parser = argparse.ArgumentParser(description="AEGIS host process containment daemon")
    parser.add_argument("--gateway", default=None, help=f"gateway WebSocket URL (default: $AEGIS_GATEWAY or {DEFAULT_GATEWAY})")
    parser.add_argument("--host-id", default=socket.gethostname())
    parser.add_argument("--interval", type=float, default=SCAN_INTERVAL_SECONDS)
    parser.add_argument("--rogue-cpu", type=float, default=90.0, help="CPU %% (per core, as psutil reports) that counts as hot")
    parser.add_argument("--rogue-scans", type=int, default=3, help="consecutive hot scans before a process is flagged rogue")
    parser.add_argument("--rogue-rss-mb", type=float, default=4096.0, help="RSS MB that flags a process rogue immediately")
    parser.add_argument(
        "--watch",
        default=os.environ.get("AEGIS_WATCH", ",".join(DEFAULT_WATCH_TOKENS)),
        help="comma-separated process-name fragments to monitor and allow control of (default: %(default)s)",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if not is_privileged():
        LOG.warning("not running as administrator/root: processes owned by other users cannot be controlled")

    scanner = ProcessScanner(args.rogue_cpu, args.rogue_rss_mb, args.rogue_scans, tuple(args.watch.split(",")))
    gateway, token = resolve_connection(args.gateway)
    url = build_url(gateway, args.host_id)
    warn_if_cleartext(url, token)
    LOG.info("watching process names containing: %s", ", ".join(scanner.watch_tokens))
    daemon = SecurityDaemon(url, args.host_id, scanner, args.interval, token)
    try:
        asyncio.run(daemon.run_forever())
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
