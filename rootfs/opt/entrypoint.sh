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

# ── Persist ADB keys across ALL addon lifecycle events ──
# /data/.android/ survives restarts/rebuilds but is WIPED on uninstall.
# /share/.vw-relay/.android/ survives everything including uninstall.
SHARE_ANDROID="/share/.vw-relay/.android"
DATA_ANDROID="/data/.android"

mkdir -p "${SHARE_ANDROID}" "${DATA_ANDROID}"

# Migrate: if key exists in /data but not /share, copy it over
if [ -f "${DATA_ANDROID}/adbkey" ] && [ ! -f "${SHARE_ANDROID}/adbkey" ]; then
    echo "Migrating ADB key from /data to /share for uninstall persistence..."
    cp "${DATA_ANDROID}/adbkey" "${SHARE_ANDROID}/adbkey"
    cp "${DATA_ANDROID}/adbkey.pub" "${SHARE_ANDROID}/adbkey.pub" 2>/dev/null || true
fi

# Restore: if key exists in /share but not /data (post-uninstall reinstall)
if [ -f "${SHARE_ANDROID}/adbkey" ] && [ ! -f "${DATA_ANDROID}/adbkey" ]; then
    echo "Restoring ADB key from /share (survived uninstall)..."
    cp "${SHARE_ANDROID}/adbkey" "${DATA_ANDROID}/adbkey"
    cp "${SHARE_ANDROID}/adbkey.pub" "${DATA_ANDROID}/adbkey.pub" 2>/dev/null || true
fi

# Symlink ~/.android → /data/.android (ADB's working copy)
rm -rf /root/.android 2>/dev/null || true
ln -sf "${DATA_ANDROID}" /root/.android

if [ -f "${DATA_ANDROID}/adbkey" ]; then
    echo "Reusing persisted ADB key (backed up to /share/.vw-relay/)"
else
    echo "No ADB key found — will be generated on first ADB use"
fi

# After ADB generates a key, back it up to /share (runs in background)
(
    while [ ! -f "${DATA_ANDROID}/adbkey" ]; do sleep 10; done
    if [ ! -f "${SHARE_ANDROID}/adbkey" ]; then
        cp "${DATA_ANDROID}/adbkey" "${SHARE_ANDROID}/adbkey"
        cp "${DATA_ANDROID}/adbkey.pub" "${SHARE_ANDROID}/adbkey.pub" 2>/dev/null || true
        echo "ADB key backed up to /share/.vw-relay/ for uninstall persistence"
    fi
) &

# ── Play Integrity fingerprint auto-updater ──
# Runs update_pif.sh on startup and every 60 minutes to keep
# the phone's PIF fingerprint fresh (Google bans them periodically).
PIF_UPDATE_INTERVAL=3600  # 1 hour in seconds

(
    # Wait for ADB device to connect
    while ! adb devices 2>/dev/null | grep -q "device$"; do sleep 10; done
    sleep 30  # let boot settle

    echo "PIF: Starting auto-updater (interval: ${PIF_UPDATE_INTERVAL}s)"
    # First run: use --reboot so Zygisk reloads with new props if changed
    sh /opt/update_pif.sh --reboot || echo "PIF: Initial update failed (will retry)"

    while true; do
        sleep ${PIF_UPDATE_INTERVAL}
        # Hourly: reboot only if fingerprint actually changed
        sh /opt/update_pif.sh --reboot || echo "PIF: Scheduled update failed (will retry next cycle)"
    done
) &

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

    # Force-restart VW app to ensure fresh API calls on launch
    echo "Force-restarting VW app..."
    adb shell "am force-stop ${VW_PACKAGE}" 2>/dev/null || true
    sleep 2
    adb shell "am start -n ${VW_PACKAGE}/com.vw.myVW.activities.RoutingActivity" 2>/dev/null || true
    sleep 5

    # Keep screen on while plugged in (developer setting)
    adb shell "settings put global stay_on_while_plugged_in 3" 2>/dev/null || true
}

# ── Watchdog loop: auto-restart on crash/disconnect ──
RESTART_DELAY=10
MAX_DELAY=120
CONSECUTIVE_FAST_EXITS=0
while true; do
    ensure_phone_ready

    echo "Starting relay at $(date '+%H:%M:%S')..."
    START_TIME=$(date +%s)
    ${CMD}
    EXIT_CODE=$?
    END_TIME=$(date +%s)
    RUNTIME=$((END_TIME - START_TIME))

    echo "Relay exited with code ${EXIT_CODE} after ${RUNTIME}s. Restarting in ${RESTART_DELAY}s..."

    # Track rapid crashes for exponential backoff
    if [ "${RUNTIME}" -lt 30 ]; then
        CONSECUTIVE_FAST_EXITS=$((CONSECUTIVE_FAST_EXITS + 1))
        echo "Fast exit #${CONSECUTIVE_FAST_EXITS}"
        # Exponential backoff: 10, 20, 40, 80, 120 (cap)
        RESTART_DELAY=$((10 * (2 ** (CONSECUTIVE_FAST_EXITS - 1))))
        [ "${RESTART_DELAY}" -gt "${MAX_DELAY}" ] && RESTART_DELAY=${MAX_DELAY}
    else
        CONSECUTIVE_FAST_EXITS=0
        RESTART_DELAY=10
    fi

    sleep ${RESTART_DELAY}

    # Only kill ADB server after persistent failures (not every restart)
    if [ "${CONSECUTIVE_FAST_EXITS}" -ge 3 ]; then
        echo "Multiple fast crashes — resetting ADB server..."
        adb kill-server 2>/dev/null || true
        sleep 2
    fi
done
