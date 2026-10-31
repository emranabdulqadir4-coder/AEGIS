# Security

AEGIS can suspend and kill processes on the machines where the daemon runs, so treat it like remote-administration software.

## Reporting a vulnerability

Please report security issues privately (GitHub "Report a vulnerability" on this repository) rather than opening a public issue. Include steps to reproduce and the version/commit.

## Threat model in one paragraph

- The **daemon** only ever controls processes whose name matches its watch list, never itself or its ancestors, and refuses a command if the target's start time does not match (PID reuse).
- The **control plane** authenticates daemons with a shared token (`Authorization: Bearer …`) and operators with a password and a signed, HttpOnly, SameSite=Strict session cookie. Failed logins are rate-limited. WebSockets reject cross-site origins.
- It will **refuse to start on a non-local address** without both `AEGIS_TOKEN` and `AEGIS_DASHBOARD_PASSWORD`.
- **Not included:** TLS termination (run behind a reverse proxy such as Caddy or nginx and use `wss://`), multi-user accounts, per-user roles, and a persistent audit log (control-plane actions are written to the server log with an `AUDIT` prefix).
