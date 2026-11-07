#!/usr/bin/env bash
# Hardened stdio launcher for the pihole MCP container.
# This is the command OpenCode spawns (see ~/.config/opencode/opencode.json).
#
# Sandbox mirrors the glnet/gmail/yahoo launchers: read-only rootfs, all
# capabilities dropped, no new privileges, no TTY, pid/memory limits. The only
# thing that leaves the container is HTTP to the Pi-hole on the LAN.
#
# Secret handling: the app password is NEVER passed as an env var, because env
# is readable through `docker inspect`. It is staged onto tmpfs
# ($XDG_RUNTIME_DIR, mode 700 dir + 600 file, never hits disk) and
# bind-mounted read-only into the container at /run/secrets/pihole.password,
# then removed when we exit.
#
# Secret source: ~/.config/opencode/pihole.password (mode 600). TPM sealing
# like glnet's is a possible upgrade; not wired here yet.
#
# Keep comments OUT of the docker run block: a '#' line inside a backslash
# continuation truncates the command.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${PIHOLE_MCP_IMAGE:-pihole-mcp:1.0.0}"
PLAIN="${PIHOLE_PASSWORD_FILE:-$HOME/.config/opencode/pihole.password}"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "pihole-mcp: image $IMAGE not found. Build it:" >&2
  echo "  docker build -t $IMAGE $DIR" >&2
  exit 1
fi

if [ ! -f "$PLAIN" ]; then
  echo "pihole-mcp: no app password found at $PLAIN" >&2
  echo "  create one in the Pi-hole web UI (Settings -> API / Web Interface)," >&2
  echo "  then: umask 077 && read -rs pw && printf '%s' \"\$pw\" > $PLAIN && echo" >&2
  exit 1
fi

# --- stage the secret on tmpfs ---------------------------------------------
RUNTIME="${XDG_RUNTIME_DIR:-/tmp}"
if [ ! -d "$RUNTIME" ]; then
  echo "pihole-mcp: XDG_RUNTIME_DIR ($RUNTIME) does not exist" >&2
  exit 1
fi
STAGE_DIR="$(mktemp -d "$RUNTIME/pihole-mcp.XXXXXX")"
chmod 700 "$STAGE_DIR"
STAGED="$STAGE_DIR/pihole.password"

cleanup() {
  # Remove the plaintext before anything else can read it. Not a shred: the
  # backing store is tmpfs, so there is no on-disk copy to overwrite.
  rm -f "$STAGED" 2>/dev/null || true
  rmdir "$STAGE_DIR" 2>/dev/null || true
}

on_signal() { cleanup; trap - INT TERM; exit 143; }
trap cleanup EXIT
trap on_signal INT TERM

# Sweep staging dirs left behind by a SIGKILLed launcher, but never one that a
# live container still has bind-mounted (a long session reads it lazily at
# every re-login; deleting it mid-flight breaks the next re-auth).
in_use="$(docker ps -q --filter name=pihole-mcp- 2>/dev/null \
  | xargs -r docker inspect -f '{{range .Mounts}}{{.Source}}
{{end}}' 2>/dev/null)"
while IFS= read -r dir; do
  [ -d "$dir" ] || continue
  case "$in_use" in
    *"$dir/"*) continue ;;   # a live container is reading this file
  esac
  [ "$(find "$dir" -maxdepth 0 -mmin +60 2>/dev/null)" ] || continue
  rm -rf "$dir"
done < <(find "$RUNTIME" -maxdepth 1 -name 'pihole-mcp.*' -type d 2>/dev/null)

# Reap orphaned containers from earlier launches. The container name carries
# the launcher's PID, so liveness is checkable without guessing: /proc/<pid>
# works for processes we do not own, where `kill -0` would also report EPERM.
for name in $(docker ps --filter name=pihole-mcp- --format '{{.Names}}' 2>/dev/null); do
  pid="${name##*-}"
  if [[ "$pid" =~ ^[0-9]+$ ]] && [ ! -d "/proc/$pid" ]; then
    echo "pihole-mcp: reaping orphaned container $name (launcher $pid is gone)" >&2
    docker rm -f "$name" >/dev/null 2>&1 || true
  fi
done

install -m 600 "$PLAIN" "$STAGED"

# Watchdog. docker has no "exit when the client dies" flag, and this launcher
# cannot background `docker run` in order to wait on it -- a backgrounded
# command in a non-interactive shell gets stdin from /dev/null, which is the
# MCP channel. So a detached subshell watches for this launcher to vanish and
# tears the container down behind it. A SIGKILL to the launcher reparents this
# subshell instead of killing it, so it still fires; file descriptors are
# dropped so it never keeps the stdio channel open after we exit.
# `$$` inside a subshell is the MAIN shell's pid ($BASHPID is the subshell's).
(
  trap '' TERM INT HUP
  while [ -d "/proc/$$" ]; do sleep 2; done
  docker rm -f "pihole-mcp-$$" >/dev/null 2>&1 || true
  rm -f "$STAGED" 2>/dev/null || true
  rmdir "$STAGE_DIR" 2>/dev/null || true
) >/dev/null 2>&1 &
WATCHDOG_PID=$!

# Run in the FOREGROUND, not backgrounded-then-waited: a backgrounded command
# in a non-interactive shell gets its stdin redirected to /dev/null, which
# would hand the container an immediate EOF and break the MCP stdio channel.
docker run -i --rm \
  --name "pihole-mcp-$$" \
  --hostname pihole-mcp \
  --init \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 256 \
  --memory 512m \
  --user "$(id -u):$(id -g)" \
  --env HOME=/tmp \
  --env PIHOLE_URL="${PIHOLE_URL:-http://pi.hole}" \
  --env PIHOLE_READ_ONLY="${PIHOLE_READ_ONLY:-0}" \
  --env PIHOLE_PASSWORD_FILE=/run/secrets/pihole.password \
  --mount "type=bind,src=$STAGED,dst=/run/secrets/pihole.password,readonly" \
  "$IMAGE" "$@"
rc=$?
kill "$WATCHDOG_PID" 2>/dev/null || true
trap - INT TERM
cleanup
trap - EXIT
exit "$rc"
