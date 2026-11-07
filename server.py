#!/usr/bin/env python3
"""
pihole-mcp -- MCP server for Pi-hole v6, over the FTL REST API.

Talks the same JSON API the AdminLTE web interface talks (http://<pihole>/api)
from the hardened container this file runs in. Point it at your Pi-hole with
PIHOLE_URL (default: http://pi.hole, the hostname every Pi-hole answers for).

Authentication, as it actually works in FTL 6.x (learned from src/api/auth.c,
not from the OpenAPI spec, which does not describe it):

  * POST /api/auth {"password": <app-password>} returns a session id (sid).
  * Every later request carries it in the X-FTL-SID *header*. That avoids the
    cookie path entirely, which is good: cookie auth additionally requires the
    CSRF token in an X-CSRF-TOKEN header (yes, that is the header name; the
    examples elsewhere say "X-CRSF" and FTL does not read that).
  * Sessions idle out (default 30 min) and are killed when the password
    changes. Any 401 triggers exactly one re-login and one retry.
  * The app password lives in a file (PIHOLE_PASSWORD_FILE), staged onto tmpfs
    by the launcher and bind-mounted in. Never an env var: docker inspect
    leaks env.

Two things the docs got wrong for us, encoded here so nobody relearns them:
  * The domain block list is spelled "deny" in the URL space (/domains/deny/
    exact) even though the web UI calls it "block". Adlists do use "block".
  * GET /api/auth reports a session as valid without checking CSRF, so it is
    useless as an auth probe -- a real endpoint is the only honest check.

PIHOLE_READ_ONLY=1 turns every mutating tool into a refusal; the read tools
keep working. The server never edits the two config keys that could lock you
out of the web UI (app_pwhash, totp_secret) even when asked.
"""

from __future__ import annotations

import functools
import ipaddress
import json
import os
import re
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

# mcp 2.x renamed FastMCP to MCPServer; the decorator and run() surface is
# otherwise the same. Accept either so the version pin is not brittle.
try:
    from mcp.server.mcpserver import MCPServer as _Server
except ModuleNotFoundError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server

# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------


class Config:
    def __init__(self) -> None:
        self.url = os.environ.get("PIHOLE_URL", "http://pi.hole").rstrip("/")
        self.timeout = float(os.environ.get("PIHOLE_TIMEOUT", "20"))
        self.read_only = os.environ.get("PIHOLE_READ_ONLY", "0").lower() in (
            "1", "true", "yes",
        )
        # In the container the launcher bind-mounts the secret here; outside
        # it falls back to the host-side file so ./server.py works directly.
        self.password_file = Path(
            os.environ.get(
                "PIHOLE_PASSWORD_FILE",
                Path.home() / ".config" / "opencode" / "pihole.password",
            )
        )

    @property
    def api(self) -> str:
        return self.url + "/api"

    @property
    def password(self) -> str:
        try:
            return self.password_file.read_text().strip()
        except FileNotFoundError:
            raise PiHoleError(
                f"no app password at {self.password_file}",
                hint="create one in the Pi-hole web UI (Settings -> API / Web "
                     "Interface) and store it there, mode 600",
            )


CFG = Config()

# Config keys that could lock you out of the web UI or mint new credentials.
# set_config and api_raw refuse them; the web UI stays the one place that can
# change them, deliberately.
DANGEROUS_CONFIG = {
    ("webserver", "api", "pwhash"),
    ("webserver", "api", "app_pwhash"),
    ("webserver", "api", "app_pwhash_date"),
    ("webserver", "api", "totp_secret"),
    ("webserver", "api", "cli_pwhash"),
}


class PiHoleError(Exception):
    def __init__(self, message: str, *, status: int | None = None,
                 hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.status = status
        self.hint = hint


# --------------------------------------------------------------------------
# HTTP client with app-password session handling
# --------------------------------------------------------------------------


class PiHole:
    """Small stdlib HTTP client. One session, re-logged-in on 401."""

    def __init__(self) -> None:
        self._sid: str | None = None
        self._lock = threading.Lock()

    # -- session -----------------------------------------------------------

    def _login(self) -> None:
        st, j = self._raw("POST", "/auth", body={"password": CFG.password})
        sess = j.get("session", {}) if isinstance(j, dict) else {}
        if st != 200 or not sess.get("valid"):
            msg = sess.get("message") or json.dumps(j)[:160]
            raise PiHoleError(f"login failed: {msg}", status=st,
                              hint="check the app password in "
                                   f"{CFG.password_file}; if it was rotated in "
                                   "the web UI, regenerate and re-store it")
        if sess.get("totp"):
            raise PiHoleError(
                "TOTP is enabled on this Pi-hole; this server does not do 2FA",
                hint="disable 2FA in Settings or run a session-based client "
                     "that can supply the token",
            )
        self._sid = sess["sid"]

    # -- plumbing ----------------------------------------------------------

    def _raw(self, method: str, path: str, *, params: dict | None = None,
             body: Any = None) -> tuple[int, Any]:
        url = CFG.api + path
        if params:
            url += "?" + urllib.parse.urlencode(
                {k: v for k, v in params.items() if v is not None})
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "pihole-mcp/1.0")
        if self._sid:
            req.add_header("X-FTL-SID", self._sid)
        try:
            with urllib.request.urlopen(req, timeout=CFG.timeout) as resp:
                raw = resp.read()
                code = resp.status
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            code = exc.code
        except urllib.error.URLError as exc:
            raise PiHoleError(
                f"cannot reach {CFG.url}: {exc.reason}",
                hint="is pihole-FTL up? On a docker host: docker ps | grep pihole",
            )
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {"_raw": raw.decode(errors="replace")[:4000]}
        return code, parsed

    def request(self, method: str, path: str, *, params: dict | None = None,
                body: Any = None) -> Any:
        """One API call, with exactly one re-login retry on 401/403."""
        with self._lock:
            if self._sid is None:
                self._login()
            code, j = self._raw(method, path, params=params, body=body)
            if code in (401, 403):
                self._login()
                code, j = self._raw(method, path, params=params, body=body)
        if code >= 400:
            err = j.get("error") if isinstance(j, dict) else None
            if isinstance(err, dict):
                raise PiHoleError(err.get("message") or "request rejected",
                                  status=code, hint=err.get("hint"))
            raise PiHoleError(f"HTTP {code} from {method} {path}", status=code)
        return redact(j)

    def get(self, path: str, params: dict | None = None) -> Any:
        return self.request("GET", path, params=params)

    def post(self, path: str, body: Any = None, params: dict | None = None) -> Any:
        return self.request("POST", path, params=params, body=body)

    def put(self, path: str, body: Any = None) -> Any:
        return self.request("PUT", path, body=body)

    def patch(self, path: str, body: Any = None) -> Any:
        return self.request("PATCH", path, body=body)

    def delete(self, path: str) -> Any:
        return self.request("DELETE", path)


API = PiHole()

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def tool_safe(fn):
    """Turn API failures into structured results instead of bare tool errors."""

    @functools.wraps(fn)
    def inner(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except PiHoleError as exc:
            out: dict[str, Any] = {"error": exc.message}
            if exc.status:
                out["status"] = exc.status
            if exc.hint:
                out["hint"] = exc.hint
            return out
        except ValueError as exc:
            return {"error": str(exc)}

    return inner


def compact(result: Any, limit: int = 40_000) -> Any:
    """Keep a huge reply (full gravity!) from flooding context."""
    text = json.dumps(result)
    if len(text) <= limit:
        return result
    return {
        "_truncated": True,
        "_bytes": len(text),
        "_preview": text[:limit],
        "_note": "reply was truncated; narrow it with a filter or lower limit",
    }


# FTL returns these in the config tree to any authenticated session: the
# password and totp_secret come back pre-masked, but pwhash/app_pwhash arrive
# as real KDF hashes. They are hashes, not plaintext -- yet handing a chat
# transcript a crackable copy of your admin credential is needless exposure.
# Everything that leaves this server passes through redact().
SECRET_KEYS = {"pwhash", "app_pwhash", "cli_pwhash", "totp_secret", "password"}


def redact(node: Any) -> Any:
    if isinstance(node, dict):
        return {
            k: ("<redacted>" if k in SECRET_KEYS and isinstance(v, str) and v
                else redact(v))
            for k, v in node.items()
        }
    if isinstance(node, list):
        return [redact(x) for x in node]
    return node


def guard_write() -> None:
    if CFG.read_only:
        raise ValueError(
            "PIHOLE_READ_ONLY is set; this server will not change anything. "
            "Unset it in the launcher env to allow writes."
        )


def q(value: str) -> str:
    """Path-segment quoting. Regex domains contain / and must not break out."""
    return urllib.parse.quote(value, safe="")


def group_ids(names: list[str] | None) -> list[int] | None:
    """Resolve group names to FTL numeric ids. FTL wants ids in bodies."""
    if not names:
        return None
    known = {g.get("name"): g.get("id")
             for g in API.get("/groups").get("groups", [])}
    out = []
    for n in names:
        if n not in known:
            raise ValueError(
                f"unknown group {n!r}; existing groups: "
                + ", ".join(sorted(str(k) for k in known)))
        out.append(known[n])
    return out


def _check_config_paths(node: Any, trail: tuple[str, ...] = ()) -> None:
    """Refuse to write lockout-capable config keys, at any nesting depth."""
    if not isinstance(node, dict):
        return
    for k, v in node.items():
        path = trail + (k,)
        if path in DANGEROUS_CONFIG:
            raise ValueError(
                "refusing to change " + ".".join(path)
                + "; manage credentials and 2FA in the Pi-hole web UI only")
        _check_config_paths(v, path)


VALID_DOMAIN_TYPE = {"allow": "allow", "block": "deny", "deny": "deny"}


def domain_type(block: bool) -> str:
    return "deny" if block else "allow"


# --------------------------------------------------------------------------
# the server
# --------------------------------------------------------------------------

mcp = _Server(
    "pihole",
    instructions=(
        "Manage a Pi-hole (FTL v6) over its REST API. Start with status. "
        "Start with status. Domain entries: 'block' here means the deny list "
        "(the API spells it deny); kinds are exact or regex. Lists are "
        "subscribe URLs (gravity). Clients attach to groups. query_log filters "
        "by unix seconds; last_minutes is the easy path. The config tree is "
        "reachable via get_config/set_config; local DNS records via "
        "list_dns_records/add_dns_record/remove_dns_record, CNAME aliases via "
        "the cname trio, DHCP reservations via the dhcp trio, and any other "
        "config array item via add/remove_config_array_item; credential and "
        "2FA keys are refused by design. api_raw covers any endpoint not "
        "wrapped here, except /auth* and teleporter. Config writes need "
        "webserver.api.app_sudo=true on the Pi-hole."
    ),
)


# -- read: status & stats ---------------------------------------------------


@mcp.tool()
@tool_safe
def status() -> dict:
    """Overall health: blocking state, 24h query summary, versions, FTL info."""
    blocking = API.get("/dns/blocking")
    summary = API.get("/stats/summary")
    version = API.get("/info/version")
    ftl = API.get("/info/ftl")

    def rel(v: Any) -> Any:
        return v.get("value") if isinstance(v, dict) and "value" in v else v

    return {
        "blocking": rel(blocking.get("blocking")),
        "blocking_until": rel(blocking.get("until")),
        "queries": rel(summary),
        "versions": {
            "core": rel(version.get("core", {}).get("local", {})),
            "web": rel(version.get("web", {}).get("local", {})),
            "ftl": rel(version.get("ftl", {}).get("local", {})),
            "update_available": rel(version.get("ftl", {}).get("update_available")),
        },
        "ftl": {
            "uptime_seconds": ftl.get("uptime"),
            "gravity_last_update": ftl.get("gravity", {}).get("last_update")
            if isinstance(ftl.get("gravity"), dict) else ftl.get("gravity_last_update"),
        },
    }


@mcp.tool()
@tool_safe
def query_log(last_minutes: int | None = None, length: int = 50,
              domain: str | None = None, client: str | None = None,
              status: str | None = None, reply: str | None = None,
              type: str | None = None, start: int = 0,
              cursor: int | None = None) -> dict:
    """Recent DNS queries, newest first. last_minutes restricts the window.

    length is capped at 500. status/reply/type take FTL codes or names; call
    query_suggestions() to see the values this FTL accepts."""
    length = max(1, min(int(length), 500))
    params: dict[str, Any] = {
        "length": length, "start": start, "cursor": cursor,
        "domain": domain, "status": status,
        "reply": reply, "type": type,
    }
    # FTL filters clients by two distinct params: IPv4/IPv6 go to client_ip,
    # everything else (hostnames) to client_name. Colons never appear in
    # hostnames, so the split is unambiguous.
    if client:
        if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", client) or ":" in client:
            params["client_ip"] = client
        else:
            params["client_name"] = client
    if last_minutes:
        now = int(__import__("time").time())
        params["from"] = now - int(last_minutes) * 60
    return compact(API.get("/queries", params))


@mcp.tool()
@tool_safe
def query_suggestions() -> dict:
    """The filter values this FTL currently knows: domains, clients, types,
    statuses, replies. Use these in query_log."""
    return compact(API.get("/queries/suggestions"))


@mcp.tool()
@tool_safe
def top_domains(blocked: bool = True, n: int = 10, database: bool = False) -> dict:
    """Top queried domains. blocked=True = most-blocked; database=True reads
    long-term storage instead of FTL's live 24h window."""
    path = "/stats/database/top_domains" if database else "/stats/top_domains"
    return API.get(path, {"n": max(1, min(int(n), 50)), "blocked":
                          "true" if blocked else "false"})


@mcp.tool()
@tool_safe
def top_clients(n: int = 10, database: bool = False) -> dict:
    """Clients that send the most queries."""
    path = "/stats/database/top_clients" if database else "/stats/top_clients"
    return API.get(path, {"n": max(1, min(int(n), 50))})


@mcp.tool()
@tool_safe
def query_types(database: bool = False) -> dict:
    """Query-type mix (A, AAAA, PTR, ...) of recent traffic."""
    return API.get("/stats/database/query_types" if database
                   else "/stats/query_types")


@mcp.tool()
@tool_safe
def upstreams(database: bool = False) -> dict:
    """Which upstream resolvers answered recent queries, and how often."""
    return API.get("/stats/database/upstreams" if database
                   else "/stats/upstreams")


@mcp.tool()
@tool_safe
def recent_blocked() -> dict:
    """The most recently blocked domain, with when and why."""
    return API.get("/stats/recent_blocked")


@mcp.tool()
@tool_safe
def activity(interval_hours: int = 24, client: str | None = None,
             database: bool = False) -> dict:
    """Time series of queries (total/blocked per bucket) for graphing."""
    n = max(1, min(int(interval_hours), 9999))
    if client:
        path = "/history/database/clients" if database else "/history/clients"
        return compact(API.get(path, {"interval": n}))
    return compact(API.get("/history/database" if database else "/history",
                           {"interval": n}))


@mcp.tool()
@tool_safe
def search_domain(domain: str) -> dict:
    """Where a domain stands: on a gravity list? exact/regex allow or deny
    entry? Also returns matching regex entries. Cheap way to answer 'why is
    X blocked'."""
    return compact(API.get(f"/search/{q(domain)}"))


# -- read: configuration state ----------------------------------------------


@mcp.tool()
@tool_safe
def list_domains(list_type: str = "block", kind: str | None = None,
                 contains: str | None = None, limit: int = 100) -> dict:
    """Custom allow/deny entries. list_type: block (deny) or allow; kind:
    exact or regex (default both). contains filters the entry text."""
    t = VALID_DOMAIN_TYPE.get(list_type.lower())
    if not t:
        raise ValueError("list_type must be 'block' or 'allow'")
    path = f"/domains/{t}" + (f"/{kind}" if kind else "")
    data = API.get(path).get("domains", [])
    if contains:
        needle = contains.lower()
        data = [d for d in data if needle in str(d.get("domain", "")).lower()]
    total = len(data)
    return compact({"total": total, "shown": min(total, int(limit)),
                    "domains": data[: int(limit)]})


@mcp.tool()
@tool_safe
def list_lists(list_type: str | None = None, contains: str | None = None,
               limit: int = 100) -> dict:
    """Subscribe lists. list_type: gravity (blocklists), audit, allow, block."""
    params = {"type": list_type} if list_type else None
    data = API.get("/lists", params).get("lists", [])
    if contains:
        needle = contains.lower()
        data = [l for l in data if needle in str(l.get("address", "")).lower()]
    total = len(data)
    return compact({"total": total, "shown": min(total, int(limit)),
                    "lists": data[: int(limit)]})


@mcp.tool()
@tool_safe
def list_groups() -> dict:
    """All groups with their ids. Group names are what add_domain/add_client
    take; ids are what the API bodies carry (resolved for you there)."""
    return compact(API.get("/groups"))


@mcp.tool()
@tool_safe
def list_clients() -> dict:
    """Configured clients (IP/MAC/hostname -> groups)."""
    return compact(API.get("/clients"))


@mcp.tool()
@tool_safe
def get_config(element: str | None = None) -> dict:
    """The FTL configuration tree, or one element (dns, dhcp, gravity, misc,
    debug, files, webserver, ...)."""
    return compact(API.get(f"/config/{element}" if element else "/config"))


@mcp.tool()
@tool_safe
def ftl_logs(after_id: int | None = None, max_lines: int = 100) -> dict:
    """pihole-FTL log file (startup, gravity runs, errors). after_id returns
    only newer lines -- use the next_id it returns to poll incrementally."""
    j = API.get("/logs/ftl", {"id": after_id})
    logs = j.get("logs", [])
    return {"lines": logs[-int(max_lines):], "next_id": j.get("last_id"),
            "total_returned": len(logs)}


@mcp.tool()
@tool_safe
def dnsmasq_logs(after_id: int | None = None, max_lines: int = 100) -> dict:
    """dnsmasq log file (query-level detail FTL's log may omit)."""
    j = API.get("/logs/dnsmasq", {"id": after_id})
    logs = j.get("logs", [])
    return {"lines": logs[-int(max_lines):], "next_id": j.get("last_id"),
            "total_returned": len(logs)}


@mcp.tool()
@tool_safe
def messages() -> dict:
    """FTL diagnosis messages (config warnings, list failures, DB issues).
    The first place to look when something is off."""
    return compact(API.get("/info/messages"))


@mcp.tool()
@tool_safe
def system_info() -> dict:
    """Host + FTL system snapshot: CPU, memory, disk, sensors, DB sizes."""
    return compact({
        "system": API.get("/info/system"),
        "host": API.get("/info/host"),
        "database": API.get("/info/database"),
    })


@mcp.tool()
@tool_safe
def dhcp_leases() -> dict:
    """DHCP leases handed out by FTL (if it serves DHCP)."""
    return compact(API.get("/dhcp/leases"))


@mcp.tool()
@tool_safe
def network_devices() -> dict:
    """Devices on the network as FTL sees them (names, MACs, interfaces)."""
    return compact(API.get("/network/devices"))


@mcp.tool()
@tool_safe
def sessions() -> dict:
    """Active API sessions (who/what is logged in, including this one;
    app=True marks app-password sessions like ours)."""
    return compact(API.get("/auth/sessions"))


# -- write: blocking --------------------------------------------------------


@mcp.tool()
@tool_safe
def set_blocking(enabled: bool, duration_minutes: int | None = None) -> dict:
    """Turn all blocking off / on globally (like the dashboard toggle).
    duration_minutes auto-reverts afterwards; omit for permanent."""
    guard_write()
    body: dict[str, Any] = {"blocking": bool(enabled)}
    if duration_minutes:
        body["timer"] = int(duration_minutes) * 60
    return API.post("/dns/blocking", body)


@mcp.tool()
@tool_safe
def block_domain(domain: str, comment: str = "", regex: bool = False,
                 groups: list[str] | None = None) -> dict:
    """Add a domain to the block (deny) list. regex=True for pattern entries.
    groups = existing group names, default the FTL default group."""
    guard_write()
    domain = domain.strip().rstrip(".").lower()
    if not domain or " " in domain:
        raise ValueError("domain must be a single hostname or pattern")
    body: dict[str, Any] = {"domain": domain, "comment": comment,
                            "enabled": True}
    ids = group_ids(groups)
    if ids:
        body["groups"] = ids
    return API.post(f"/domains/deny/{'regex' if regex else 'exact'}", body)


@mcp.tool()
@tool_safe
def unblock_domain(domain: str, regex: bool = False) -> dict:
    """Remove an entry from the block (deny) list. For the allow list,
    use remove_domain_entries."""
    guard_write()
    domain = domain.strip().rstrip(".").lower()
    API.delete(f"/domains/deny/{'regex' if regex else 'exact'}/{q(domain)}")
    return {"removed": domain, "list": "deny"}


@mcp.tool()
@tool_safe
def allow_domain(domain: str, comment: str = "", regex: bool = False,
                 groups: list[str] | None = None) -> dict:
    """Add a domain to the allow list (whitelist)."""
    guard_write()
    domain = domain.strip().rstrip(".").lower()
    if not domain or " " in domain:
        raise ValueError("domain must be a single hostname or pattern")
    body: dict[str, Any] = {"domain": domain, "comment": comment,
                            "enabled": True}
    ids = group_ids(groups)
    if ids:
        body["groups"] = ids
    return API.post(f"/domains/allow/{'regex' if regex else 'exact'}", body)


@mcp.tool()
@tool_safe
def remove_domain_entries(entries: list[dict]) -> dict:
    """Batch-remove custom entries. Each item: {"domain": "...", "type":
    "allow"|"deny", "kind": "exact"|"regex"}. Returns per-item results; FTL
    processes the batch atomically-ish and reports failures inside the body."""
    guard_write()
    payload = []
    for e in entries:
        t = VALID_DOMAIN_TYPE.get(str(e.get("type", "deny")).lower())
        if not t:
            raise ValueError("each entry needs type allow/block/deny")
        payload.append({"item": str(e["domain"]).strip().lower(),
                        "type": t, "kind": e.get("kind", "exact")})
    if not payload:
        raise ValueError("entries is empty")
    return compact(API.post("/domains:batchDelete", payload))


# -- write: lists, groups, clients ------------------------------------------


@mcp.tool()
@tool_safe
def add_list(url: str, list_type: str = "gravity", comment: str = "",
             groups: list[str] | None = None) -> dict:
    """Subscribe to a blocklist URL (list_type gravity), an audit list, or an
    allow/block list URL. Does not download immediately -- call
    refresh_gravity after adding."""
    guard_write()
    if not url.lower().startswith(("http://", "https://", "ftp://")):
        raise ValueError("url must be http(s):// or ftp://")
    body: dict[str, Any] = {"address": url, "type": list_type,
                            "comment": comment, "enabled": True}
    ids = group_ids(groups)
    if ids:
        body["groups"] = ids
    return API.post("/lists", body)


@mcp.tool()
@tool_safe
def remove_list(url: str) -> dict:
    """Remove a subscribe list by its exact URL (see list_lists)."""
    guard_write()
    API.delete(f"/lists/{q(url)}")
    return {"removed": url}


@mcp.tool()
@tool_safe
def add_group(name: str, comment: str = "") -> dict:
    """Create a client/group (used to scope lists and entries)."""
    guard_write()
    body: dict[str, Any] = {"name": name, "comment": comment}
    return API.post("/groups", body)


@mcp.tool()
@tool_safe
def remove_group(name: str) -> dict:
    """Delete a group. The default group cannot be deleted."""
    guard_write()
    API.delete(f"/groups/{q(name)}")
    return {"removed": name}


@mcp.tool()
@tool_safe
def add_client(client: str, groups: list[str], comment: str = "") -> dict:
    """Attach a client (IP, MAC, hostname, or :interface) to groups. FTL v6
    models per-device policy as group membership; list_groups shows what
    exists (including the special allow/deny-scoped groups)."""
    guard_write()
    ids = group_ids(groups)
    if not ids:
        raise ValueError("groups is required; see list_groups")
    return API.post("/clients", {"client": client, "comment": comment,
                                 "groups": ids})


@mcp.tool()
@tool_safe
def remove_client(client: str) -> dict:
    """Remove a configured client entry (does not un-know the device)."""
    guard_write()
    API.delete(f"/clients/{q(client)}")
    return {"removed": client}


# -- write: config & maintenance --------------------------------------------


@mcp.tool()
@tool_safe
def list_dns_records() -> dict:
    """Local DNS records: 'IP hostname' entries FTL answers directly, like
    custom A records for the whole network (this is the API behind the web
    UI's Local DNS -> DNS Records page)."""
    j = API.get("/config/dns/hosts")
    return {"hosts": j.get("config", {}).get("dns", {}).get("hosts", [])}


@mcp.tool()
@tool_safe
def add_dns_record(ip: str, hostname: str) -> dict:
    """Add a local DNS record so hostname resolves to ip for every client that
    uses this Pi-hole for DNS. FTL stores these as the config array
    dns.hosts; adding needs webserver.api.app_sudo=true on the Pi-hole
    (app-password sessions cannot otherwise write config)."""
    guard_write()
    str(ipaddress.ip_address(ip.strip()))  # raises ValueError if not an IP
    hostname = hostname.strip().rstrip(".").lower()
    if not re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?"
                        r"(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*", hostname):
        raise ValueError(f"hostname {hostname!r} looks invalid")
    return API.put(f"/config/dns/hosts/{q(ip.strip() + ' ' + hostname)}")


@mcp.tool()
@tool_safe
def remove_dns_record(entry: str) -> dict:
    """Remove a local DNS record. entry is the exact 'IP hostname' string as
    shown by list_dns_records."""
    guard_write()
    entry = entry.strip()
    API.delete(f"/config/dns/hosts/{q(entry)}")
    return {"removed": entry}


@mcp.tool()
@tool_safe
def list_cname_records() -> dict:
    """Local CNAME aliases, each 'cname,target[,TTL]' (FTL answers cname as if
    it were target)."""
    j = API.get("/config/dns/cnameRecords")
    return {"cnameRecords": j.get("config", {}).get("dns", {}).get("cnameRecords", [])}


@mcp.tool()
@tool_safe
def add_cname_record(cname: str, target: str, ttl: int | None = None) -> dict:
    """Alias cname to target locally. WARNING: unlike plain DNS records,
    changing dns.cnameRecords carries FTL's restart flag -- FTL restarts
    itself, so DNS blinks for a couple of seconds. Takes effect on restart."""
    guard_write()
    for name in (cname, target):
        name = name.strip().rstrip(".").lower()
        if not re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?"
                            r"(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*", name):
            raise ValueError(f"hostname {name!r} looks invalid")
    entry = f"{cname.strip().rstrip('.').lower()},{target.strip().rstrip('.').lower()}"
    if ttl:
        entry += f",{int(ttl)}"
    return API.put(f"/config/dns/cnameRecords/{q(entry)}")


@mcp.tool()
@tool_safe
def remove_cname_record(entry: str) -> dict:
    """Remove a CNAME alias (exact 'cname,target[,TTL]' string from
    list_cname_records). Restarts FTL like add_cname_record."""
    guard_write()
    entry = entry.strip()
    API.delete(f"/config/dns/cnameRecords/{q(entry)}")
    return {"removed": entry}


MAC_RE = re.compile(r"^[0-9a-fA-F][0-9a-fA-F:._-]{10,16}[0-9a-fA-F]$")


@mcp.tool()
@tool_safe
def list_dhcp_reservations() -> dict:
    """Static DHCP leases (dns-host style 'mac,ip,hostname' entries). Only
    meaningful when FTL itself runs the DHCP server."""
    j = API.get("/config/dhcp/hosts")
    return {"hosts": j.get("config", {}).get("dhcp", {}).get("hosts", [])}


@mcp.tool()
@tool_safe
def add_dhcp_reservation(mac: str, ip: str | None = None,
                         hostname: str | None = None) -> dict:
    """Reserve a DHCP address (mac -> ip, optional hostname). Requires FTL to
    be the active DHCP server. Restarts FTL (dhcp.hosts is a restart-flagged
    setting), so DNS blinks for seconds."""
    guard_write()
    mac = mac.strip().lower().replace("-", ":")
    if not MAC_RE.fullmatch(mac):
        raise ValueError(f"{mac!r} does not look like a MAC address")
    parts = [mac]
    if ip:
        parts.append(str(ipaddress.ip_address(ip.strip())))
    if hostname:
        parts.append(hostname.strip().rstrip(".").lower())
    return API.put(f"/config/dhcp/hosts/{q(','.join(parts))}")


@mcp.tool()
@tool_safe
def remove_dhcp_reservation(entry: str) -> dict:
    """Remove a DHCP reservation (exact entry string from
    list_dhcp_reservations). Restarts FTL."""
    guard_write()
    entry = entry.strip()
    API.delete(f"/config/dhcp/hosts/{q(entry)}")
    return {"removed": entry}


# Config arrays that are safe to manage through the generic pair. Anything
# under webserver. is excluded (that is FTL's own web/API surface; editing it
# from chat is how you saw off the branch you sit on), and dnsmasq_lines /
# advancedOpts are read-only via API anyway.
GENERIC_ARRAY_OK = ("dns.", "dhcp.")
GENERIC_ARRAY_DENY = ("dns.dnsmasq_lines",)


def _guard_generic_array(element: str, key: str) -> str:
    path = f"{element}.{key}"
    if not path.startswith(GENERIC_ARRAY_OK) or path in GENERIC_ARRAY_DENY:
        raise ValueError(
            f"{path} is not manageable here; allowed prefixes: dns., dhcp., "
            "gravity., files. (webserver.* is refused by design)")
    return path


@mcp.tool()
@tool_safe
def add_config_array_item(element: str, key: str, value: str) -> dict:
    """Add one item to a string-array config option that has no dedicated
    tool -- e.g. dns/revServers ('true,192.168.1.0/24,192.168.1.1,lan'),
    dns/upstreams, dhcp/hosts. Item format is per-option; GET the option via
    get_config('{element}/{key}') to see existing examples. Some options
    restart FTL on change."""
    guard_write()
    _guard_generic_array(element, key)
    return API.put(f"/config/{q(element)}/{q(key)}/{q(value)}")


@mcp.tool()
@tool_safe
def remove_config_array_item(element: str, key: str, value: str) -> dict:
    """Remove one exact item from a string-array config option (see
    add_config_array_item for what is allowed)."""
    guard_write()
    _guard_generic_array(element, key)
    API.delete(f"/config/{q(element)}/{q(key)}/{q(value)}")
    return {"removed": f"{element}.{key}: {value}"}


@mcp.tool()
@tool_safe
def set_config(config: dict) -> dict:
    """Patch FTL config with a nested fragment, e.g.
    {"dns": {"upstream1": "192.168.1.1"}} or {"dhcp": {"active": true}}.
    Values must match the option's type (get_config shows current values and
    structure). Credential/2FA keys are refused; use the web UI for those."""
    guard_write()
    if not isinstance(config, dict) or not config:
        raise ValueError("config must be a non-empty object")
    # check both with and without the webserver prefix so either spelling of
    # the fragment is caught
    _check_config_paths(config)
    _check_config_paths({"webserver": config})
    return API.patch("/config", {"config": config})


@mcp.tool()
@tool_safe
def refresh_gravity() -> dict:
    """Re-download and rebuild all gravity lists. Can take minutes; returns as
    soon as FTL accepts the job. Check ftl_logs for progress."""
    guard_write()
    return API.post("/action/gravity")


@mcp.tool()
@tool_safe
def restart_ftl() -> dict:
    """Restart pihole-FTL. Brief DNS resolution outage while it
    comes back (seconds)."""
    guard_write()
    return API.post("/action/restartdns")


@mcp.tool()
@tool_safe
def flush_query_log() -> dict:
    """Empty the live query log (FTL memory + today's DB rows + log file)."""
    guard_write()
    return API.post("/action/flush/logs")


@mcp.tool()
@tool_safe
def flush_arp() -> dict:
    """Flush FTL's ARP cache view."""
    guard_write()
    return API.post("/action/flush/arp")


@mcp.tool()
@tool_safe
def flush_network_cache() -> dict:
    """Flush FTL's network scan/device cache."""
    guard_write()
    return API.post("/action/flush/network")


# -- escape hatch ------------------------------------------------------------


@mcp.tool()
@tool_safe
def api_raw(method: str, path: str, body: dict | list | None = None,
            params: dict | None = None) -> dict:
    """Call any FTL endpoint not wrapped above. path starts at /api, e.g.
    "/info/sensors" or "/domains/deny/exact/evil.example". GET/HEAD always
    allowed; writes obey PIHOLE_READ_ONLY. Refuses /auth* (use the dedicated
    tools) and teleporter (bulk config import is too sharp a knife for chat).
    GET /endpoints lists everything FTL exposes."""
    method = method.upper()
    if not path.startswith("/"):
        path = "/" + path
    low = path.lower()
    if low.startswith("/auth"):
        raise ValueError("use the dedicated session tools for /auth")
    if low.startswith("/teleporter"):
        raise ValueError("teleporter is refused: bulk import can replace "
                         "credentials and whole config subtrees")
    if method not in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"):
        raise ValueError("bad method")
    if method != "GET":
        guard_write()
    if isinstance(body, dict) and "config" in body and low.startswith("/config"):
        _check_config_paths(body["config"])
    return compact(API.request(method, path, params=params, body=body))


if __name__ == "__main__":
    mcp.run()  # stdio
