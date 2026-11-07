#!/usr/bin/env python3
"""Smoke test: drive the launcher over real MCP stdio and hit live tools.

Spawns ./pihole-mcp-container.sh, does initialize -> tools/list -> a few
read tools, then a write round-trip (block + unblock a throwaway domain)
unless PIHOLE_SKIP_WRITE=1. Needs the image built and the password file.
"""
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
proc = subprocess.Popen(
    [os.path.join(HERE, "pihole-mcp-container.sh")],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    text=True, bufsize=1,
)


def send(obj):
    proc.stdin.write(json.dumps(obj) + "\n")
    proc.stdin.flush()


def recv(want_id, timeout=60):
    """Read until the response for want_id arrives; skip notifications."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            raise SystemExit("container closed the pipe early")
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("id") == want_id:
            return msg
    raise SystemExit(f"timeout waiting for response {want_id}")


def call(name, args=None, want=3):
    send({"jsonrpc": "2.0", "id": want, "method": "tools/call",
          "params": {"name": name, "arguments": args or {}}})
    r = recv(want)
    if "error" in r:
        return {"error": r["error"]}
    content = r["result"].get("content", [])
    text = content[0]["text"] if content else ""
    if r["result"].get("isError"):
        return {"error": "tool_error: " + text[:400]}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"text": text[:400]}


fails = []


def check(label, cond, detail=""):
    print(("PASS  " if cond else "FAIL  ") + label + (" " + detail if detail else ""))
    if not cond:
        fails.append(label)


send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-03-26", "capabilities": {},
    "clientInfo": {"name": "smoke", "version": "0"}}})
init = recv(1)
check("initialize", "result" in init,
      init.get("result", {}).get("serverInfo", {}).get("name", "?"))
send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
tools = recv(2)["result"]["tools"]
names = {t["name"] for t in tools}
check(f"tools/list ({len(tools)} tools)", len(tools) >= 25,
      "missing:" + str({"status", "block_domain", "api_raw"} - names or "none"))

st = call("status", want=3)
check("status: has blocking key", "blocking" in st,
      f"blocking={st.get('blocking')} ftl={st.get('versions', {}).get('ftl')}")

ql = call("query_log", {"last_minutes": 60, "length": 5}, want=4)
check("query_log: returns queries", "queries" in ql,
      f"recordsTotal={ql.get('recordsTotal')}")

td = call("top_domains", {"blocked": True, "n": 3}, want=5)
check("top_domains", "domains" in td)

sd = call("search_domain", {"domain": "example.com"}, want=6)
check("search_domain", "query" in sd or "exact_domain" in sd or "error" not in sd)

gr = call("list_groups", want=7)
check("list_groups", "groups" in gr,
      ",".join(g.get("name", "?") for g in gr.get("groups", [])[:6]))

msg = call("messages", want=8)
check("messages", "error" not in msg)

ses = call("sessions", want=9)
mine = [s for s in ses.get("sessions", []) if s.get("current_session")]
check("sessions: ours is app=True", bool(mine) and mine[0].get("app") is True)

bad = call("set_config", {"config": {"webserver": {"api": {"app_pwhash": "x"}}}},
           want=10)
check("set_config refuses credential keys", "error" in bad or "refusing" in str(bad))

raw = call("api_raw", {"method": "GET", "path": "/info/sensors"}, want=11)
check("api_raw GET", "error" not in raw)

raw2 = call("api_raw", {"method": "POST", "path": "/teleporter"}, want=12)
check("api_raw refuses teleporter", "error" in raw2 or "rpc_error" in raw2)

if not os.environ.get("PIHOLE_SKIP_WRITE"):
    b = call("block_domain", {"domain": "smoke-test.invalid",
                              "comment": "pihole-mcp smoke, auto-removed"}, want=13)
    ok_add = "error" not in b and "rpc_error" not in b
    check("block_domain add", ok_add, json.dumps(b)[:120])

    def matches(s):
        """Count real hits; /search echoes the query domain in .parameters, so
        a substring test on the whole payload is always true."""
        res = s.get("search", {}).get("results", {})
        return sum([res.get("domains", {}).get("exact", 0),
                    res.get("domains", {}).get("regex", 0),
                    res.get("gravity", {}).get("allow", 0),
                    res.get("gravity", {}).get("block", 0)])

    s = call("search_domain", {"domain": "smoke-test.invalid"}, want=14)
    check("block visible in search", matches(s) > 0)
    r = call("unblock_domain", {"domain": "smoke-test.invalid"}, want=15)
    check("unblock_domain remove", "error" not in r and "rpc_error" not in r)
    # FTL reloads gravity asynchronously after a DB change; poll briefly
    gone = False
    for _ in range(10):
        s2 = call("search_domain", {"domain": "smoke-test.invalid"}, want=16)
        if matches(s2) == 0:
            gone = True
            break
        time.sleep(1)
    check("removal visible in search", gone)

    # -- local DNS records (dns.hosts applies live, no FTL restart) ---------
    hr = call("list_dns_records", want=17)
    check("list_dns_records", "hosts" in hr)
    a = call("add_dns_record", {"ip": "192.0.2.99",
                                "hostname": "smoke-record.invalid"}, want=18)
    check("add_dns_record", "error" not in a, json.dumps(a)[:100])
    l2 = call("list_dns_records", want=19)
    check("dns record visible",
          any("smoke-record.invalid" in h for h in l2.get("hosts", [])))
    rr = call("remove_dns_record", {"entry": "192.0.2.99 smoke-record.invalid"},
              want=20)
    check("remove_dns_record", "error" not in rr)
    l3 = call("list_dns_records", want=21)
    check("dns record gone",
          not any("smoke-record.invalid" in h for h in l3.get("hosts", [])))

    # -- validation paths (no API write should happen) ----------------------
    bad1 = call("add_dns_record", {"ip": "not-an-ip", "hostname": "x.lan"},
                want=22)
    check("add_dns_record rejects bad ip", "error" in bad1)
    bad2 = call("add_cname_record", {"cname": "bad name!", "target": "pi.hole"},
                want=23)
    check("add_cname_record rejects bad name", "error" in bad2)
    bad3 = call("add_dhcp_reservation", {"mac": "zz:zz"}, want=24)
    check("add_dhcp_reservation rejects bad mac", "error" in bad3)
    bad4 = call("add_config_array_item",
                {"element": "webserver", "key": "headers", "value": "X: y"},
                want=25)
    check("generic array tool refuses webserver.*", "error" in bad4)

    # credential hashes must never reach the model's context
    wcfg = call("get_config", {"element": "webserver"}, want=26)
    dump = json.dumps(wcfg)
    check("config responses redact password hashes",
          "<redacted>" in dump and "BALLOON" not in dump and "$y$" not in dump)

send({"jsonrpc": "2.0", "id": 99, "method": "tools/call", "params": {
    "name": "sessions", "arguments": {}}})  # keep pipe warm till here
proc.stdin.close()
try:
    proc.wait(timeout=15)
except subprocess.TimeoutExpired:
    proc.kill()

print()
print("SMOKE " + ("OK" if not fails else f"FAILED: {fails}"))
sys.exit(1 if fails else 0)
