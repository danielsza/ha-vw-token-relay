#!/bin/sh

OPTIONS="/data/options.json"

MQTT_HOST=$(jq -r '.mqtt_host' "$OPTIONS")
MQTT_PORT=$(jq -r '.mqtt_port' "$OPTIONS")
MQTT_USER=$(jq -r '.mqtt_user // empty' "$OPTIONS")
MQTT_PASS=$(jq -r '.mqtt_pass // empty' "$OPTIONS")
MQTT_TOPIC=$(jq -r '.mqtt_topic' "$OPTIONS")
VW_PACKAGE=$(jq -r '.vw_package' "$OPTIONS")
BASE_URL=$(jq -r '.base_url' "$OPTIONS")
VW_USERNAME=$(jq -r '.vw_username // empty' "$OPTIONS")
VW_PASSWORD=$(jq -r '.vw_password // empty' "$OPTIONS")
VW_SPIN=$(jq -r '.vw_spin // empty' "$OPTIONS")
LOG_LEVEL=$(jq -r '.log_level' "$OPTIONS")

# ── Persist ADB keys across container restarts/rebuilds ──
# ADB stores keys at ~/.android/adbkey. Default HOME is /root.
# Symlink /root/.android → /data/.android so the key survives
# container recreation (restarts, rebuilds, reboots).
mkdir -p /data/.android
rm -rf /root/.android 2>/dev/null || true
ln -sf /data/.android /root/.android

# If no key exists yet, let ADB generate one naturally on first use.
# The phone must authorize once; after that the key persists.
if [ -f /data/.android/adbkey ]; then
    echo "Reusing persisted ADB key from /data/.android/"
else
    echo "No ADB key found — will be generated on first ADB use"
fi

echo "============================================="
echo "  VW Token Relay — Starting"
echo "============================================="
echo "  MQTT: ${MQTT_HOST}:${MQTT_PORT}"
echo "  Topic: ${MQTT_TOPIC}"
echo "  VW Package: ${VW_PACKAGE}"
echo "  Log Level: ${LOG_LEVEL}"
echo "============================================="

# Export config for the relay script to pick up
export VW_PACKAGE="${VW_PACKAGE}"
export BASE_URL="${BASE_URL}"
export LOG_LEVEL="${LOG_LEVEL}"

# Build relay command args
CMD="/opt/venv/bin/python3 /opt/vw_token_relay.py"
CMD="${CMD} --mqtt-host ${MQTT_HOST}"
CMD="${CMD} --mqtt-port ${MQTT_PORT}"
[ -n "${MQTT_USER}" ] && CMD="${CMD} --mqtt-user ${MQTT_USER}"
[ -n "${MQTT_PASS}" ] && CMD="${CMD} --mqtt-pass ${MQTT_PASS}"
[ -n "${VW_USERNAME}" ] && CMD="${CMD} --vw-email ${VW_USERNAME}"
[ -n "${VW_PASSWORD}" ] && CMD="${CMD} --vw-password ${VW_PASSWORD}"
[ -n "${VW_SPIN}" ] && CMD="${CMD} --vw-spin ${VW_SPIN}"

wake_screen() {
    # Wake screen and dismiss lock screen (no PIN assumed)
    SCREEN_STATE=$(adb shell "dumpsys power | grep 'Display Power'" 2>/dev/null || echo "unknown")
    if echo "${SCREEN_STATE}" | grep -q "state=OFF"; then
        echo "Screen off — waking..."
        adb shell "input keyevent KEYCODE_WAKEUP" 2>/dev/null || true
        sleep 1
        # Swipe up to dismiss lock screen
        adb shell "input swipe 540 1800 540 800 300" 2>/dev/null || true
        sleep 1
    fi
}

ensure_phone_ready() {
    # Wait for ADB device
    echo "Waiting for USB device..."
    while ! adb devices 2>/dev/null | grep -q "device$"; do
        sleep 5
    done
    DEVICE=$(adb devices | grep "device$" | head -1 | awk '{print $1}')
    echo "Found ADB device: ${DEVICE}"

    # Ensure frida-server is running on the phone
    if ! adb shell "pidof frida-server" > /dev/null 2>&1; then
        echo "Starting frida-server on phone..."
        adb shell "su -c '/data/local/tmp/frida-server -D &'" 2>/dev/null || true
        sleep 3
    fi

    # Wake screen so app can launch properly
    wake_screen

    # Launch VW app if not running
    if ! adb shell "pidof ${VW_PACKAGE}" > /dev/null 2>&1; then
        echo "Launching VW app..."
        adb shell "am start -n ${VW_PACKAGE}/com.vw.myVW.activities.RoutingActivity" 2>/dev/null || true
        sleep 5
    fi

    # Keep screen on while plugged in (developer setting)
    adb shell "settings put global stay_on_while_plugged_in 3" 2>/dev/null || true
}

# ── Watchdog loop: auto-restart on crash/disconnect ──
RESTART_DELAY=10
while true; do
    ensure_phone_ready

    echo "Starting relay..."
    ${CMD}
    EXIT_CODE=$?

    echo "Relay exited with code ${EXIT_CODE}. Restarting in ${RESTART_DELAY}s..."
    sleep ${RESTART_DELAY}

    # Kill stale ADB server so it reconnects cleanly
    adb kill-server 2>/dev/null || true
    sleep 2
done
