ARG BUILD_FROM
FROM ${BUILD_FROM}

# Install system dependencies (Debian-based)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    adb \
    jq \
    socat \
    && python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir \
        frida==16.5.9 \
        frida-tools==13.6.1 \
        paho-mqtt \
        PyJWT \
        cryptography \
        Pillow \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Force layer invalidation — change this string to bust Docker cache
RUN echo "force-rebuild-20260916-0005" > /tmp/.build_marker

# Copy relay script and entrypoint
COPY rootfs /

RUN chmod +x /opt/entrypoint.sh /opt/update_pif.sh

ENTRYPOINT ["/opt/entrypoint.sh"]
