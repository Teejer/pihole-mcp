# pihole-mcp

MCP server for Pi-hole v6 (FTL), over its REST API. Runs in a hardened Docker
container and exposes ~50 tools: status/stats, query log, allow/deny entries,
subscribe lists, groups, clients, local DNS records, CNAME aliases, DHCP
reservations, config, and maintenance actions.

Built from scratch rather than adopting a community server (the existing ones
were small and unaudited), with a focus on verified behavior: several things
the official docs describe do not match FTL 6.x, and were learned by reading
FTL's C source. Those findings are encoded in `server.py` and listed below.

## Files

| file | role |
|---|---|
| `server.py` | the MCP server (stdio) |
| `Dockerfile` | python:3.14-slim, non-root, no version-specific data baked in |
| `pihole-mcp-container.sh` | hardened stdio launcher (OpenCode-style `local` MCP entry) |
| `test_smoke.py` | live end-to-end test: real MCP handshake + tool round-trips |
| `spec/` | the OpenAPI fragments **as served by FTL 6.8** (`GET /api/docs/specs/*.yaml`), the build reference |

## Setup

1. **Create an app password** in the Pi-hole web UI (Settings → API / Web
   Interface). Store the plaintext at
   `~/.config/opencode/pihole.password` (or point `PIHOLE_PASSWORD_FILE`
   elsewhere), mode 600.
2. **Enable config writes if you want them**: FTL refuses config changes from
   app-password sessions unless `webserver.api.app_sudo` is true
   (Settings → Advanced, or `PATCH /api/config` from a web-password session).
   Reads and list management work without it.
3. **Build and test**:
   ```sh
   docker build -t pihole-mcp:1.0.0 .
   PIHOLE_URL=http://<your-pihole> python3 test_smoke.py
   ```
4. **Register with your MCP client** as a stdio/local server running
   `pihole-mcp-container.sh`. Useful env for the launcher: `PIHOLE_URL`
   (default `http://pi.hole`), `PIHOLE_READ_ONLY=1` (all mutating tools
   refuse; reads keep working).

## Auth model (FTL 6.x, verified against src/api/auth.c)

* `POST /api/auth {"password": <app-password>}` → session id.
* Carry it in the **`X-FTL-SID` header** on every call. The header path skips
  the CSRF requirement that cookie auth imposes (cookie auth needs the token
  in `X-CSRF-TOKEN` -- the spec examples' `X-CRSF` is not read by FTL).
* Sessions idle out (default 30 min) and die when the password rotates; the
  server re-logs in once per 401 automatically.
* The app-password session shows as `app: true` in `GET /api/auth/sessions`,
  separate from interactive web sessions.

## Gotchas encoded in server.py

* The domain **block list is `deny`** in the URL space (`/domains/deny/exact`)
  even though the UI says "block". Adlists do use `block`.
* `GET /api/auth` reports a session valid without checking CSRF -- useless as
  an auth probe; only a real endpoint is an honest check.
* Local DNS records, CNAME aliases, and DHCP reservations are not dedicated
  endpoints: they are **config string-arrays** (`dns.hosts`,
  `dns.cnameRecords`, `dhcp.hosts`) managed via
  `PUT/DELETE /config/{element}/{array}/{item}`. `dns.hosts` applies live;
  the other two carry FTL's restart flag.
* `POST /domains/{type}/{kind}` wants group **ids**; the tools resolve group
  **names** for you (`list_groups` to discover).
* `PUT` on a config array item answers **201**, `DELETE` answers **204**.
* Credential/2FA config keys (`webserver.api.pwhash`, `app_pwhash`,
  `totp_secret`, ...) are refused by `set_config`/`api_raw` by design -- a
  chat misfire must not be able to lock the web UI.

## Safety

* `PIHOLE_READ_ONLY=1` makes every mutating tool refuse.
* `api_raw` reaches any endpoint **except** `/auth*` and teleporter (bulk
  config import is too sharp a knife for chat).
* The generic array-item tool refuses `webserver.*`.
* The container: `--read-only`, `--cap-drop ALL`, `--security-opt
  no-new-privileges`, pids/memory limits.
* The app password is never an env var or CLI arg (docker inspect leaks
  env): the launcher stages it on tmpfs and bind-mounts it read-only at
  `/run/secrets/pihole.password`, removing it on exit.

## Refreshing the spec snapshot

`spec/` is what our FTL 6.8 serves at `/api/docs/specs/*.yaml`. If a tool
starts returning 400s after an FTL upgrade, re-download it and diff.

## License

MIT. The `spec/` directory contains the API documentation as distributed by
Pi-hole FTLDNS (c) Pi-hole LLC.
