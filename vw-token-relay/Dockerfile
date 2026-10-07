ARG BUILD_FROM
FROM ${BUILD_FROM}

# Install system dependencies (Debian-based)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    adb \
    fastboot \
    jq \
    socat \
    nodejs \
    npm \
    && python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir \
        frida==17.22.2 \
        frida-tools==14.11.0 \
        paho-mqtt \
        PyJWT \
        cryptography \
        Pillow \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Compile Frida agent with bundled frida-java-bridge
# (Java bridge is decoupled from Frida 17+ core runtime)
COPY frida-agent/ /tmp/frida-agent/
RUN cd /tmp/frida-agent \
    && npm install --no-audit --no-fund \
    && npx frida-compile agent.js -o /opt/compiled_agent.js \
    && rm -rf /tmp/frida-agent

# Force layer invalidation — change this string to bust Docker cache
RUN echo "force-rebuild-20261006-esm-java-bridge" > /tmp/.build_marker

# Copy relay script and entrypoint
COPY rootfs /

RUN chmod +x /opt/entrypoint.sh /opt/update_pif.sh

ENTRYPOINT ["/opt/entrypoint.sh"]
