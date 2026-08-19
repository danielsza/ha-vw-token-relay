ARG BUILD_FROM
FROM ${BUILD_FROM}

# Install system dependencies
RUN apk add --no-cache \
    python3 \
    py3-pip \
    android-tools \
    build-base \
    python3-dev \
    libffi-dev \
    linux-headers \
    jq \
    && python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir \
        frida==16.5.9 \
        frida-tools==13.6.1 \
        paho-mqtt \
        PyJWT \
    && apk del build-base python3-dev libffi-dev linux-headers

# Copy relay script and entrypoint
COPY rootfs /

RUN chmod +x /opt/entrypoint.sh

ENTRYPOINT ["/opt/entrypoint.sh"]
