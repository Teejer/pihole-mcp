# pihole-mcp -- MCP server for Pi-hole v6 (FTL REST API).
#
# Nothing here needs compiling: the server is pure Python stdlib HTTP. The
# image carries no version-specific knowledge about the Pi-hole; it is the
# same image for any FTL 6.x.

FROM python:3.14-slim

# A non-root user exists so the image is safe to run without an explicit
# --user, but the launcher overrides this with your real uid/gid anyway so
# that the bind-mounted secret file is readable without granting group
# access.
RUN groupadd -g 10000 pihole \
 && useradd -m -u 10000 -g 10000 -s /usr/sbin/nologin pihole

WORKDIR /app

# Dependencies first so the layer survives edits to server.py.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py ./

USER 10000:10000

# The launcher stages the secret onto tmpfs and bind-mounts it here.
# Deliberately not an ENV: env vars are readable via `docker inspect`.
ENV PIHOLE_PASSWORD_FILE=/run/secrets/pihole.password \
    HOME=/tmp \
    PYTHONUNBUFFERED=1

ENTRYPOINT ["python", "-u", "/app/server.py"]
