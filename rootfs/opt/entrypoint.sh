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
# DISABLED: Running action.sh during/after boot caused phone boot loops.
# PIF fingerprint updates should be triggered manually via MQTT:
#   mosquitto_pub -t vw/cmd/update_pif -m ""
echo "PIF auto-updater: DISABLED (manual via vw/cmd/update_pif)"

# ── Auto-install PIF module if missing ──
# Downloads and installs chiteroman's PlayIntegrityFix via Magisk CLI.
# Does NOT run action.sh (which caused boot loops). Uses built-in fingerprint.
(
    while ! adb devices 2>/dev/null | grep -q "device$"; do sleep 5; done
    sleep 5  # Let phone finish booting

    if adb shell "su -c 'test -d /data/adb/modules/playintegrityfix'" 2>/dev/null || \
       adb shell "su -c 'test -d /data/adb/modules/playintegrityfork'" 2>/dev/null; then
        echo "PIF: Module already installed, skipping"
    else
        echo "PIF: Module not found — installing PlayIntegrityFork (osm0sis)..."
        PIF_VERSION="v17"
        PIF_URL="https://github.com/osm0sis/PlayIntegrityFork/releases/download/${PIF_VERSION}/PlayIntegrityFork-${PIF_VERSION}.zip"

        echo "PIF: Downloading ${PIF_VERSION} from GitHub..."
        if wget -q -O /tmp/pif_module.zip "${PIF_URL}" 2>/dev/null || \
           /opt/venv/bin/python3 -c "import urllib.request; urllib.request.urlretrieve('${PIF_URL}', '/tmp/pif_module.zip')" 2>/dev/null; then

            echo "PIF: Pushing to phone..."
            adb push /tmp/pif_module.zip /data/local/tmp/pif_module.zip 2>&1

            echo "PIF: Installing via Magisk..."
            adb shell "su -c 'magisk --install-module /data/local/tmp/pif_module.zip'" 2>&1
            INSTALL_RC=$?

            if [ "$INSTALL_RC" -eq 0 ]; then
                echo "PIF: Module installed successfully!"
                # Remove auto-update scripts to prevent boot loops
                adb shell "su -c 'rm -f /data/adb/modules/playintegrityfork/action.sh'" 2>/dev/null || true
                adb shell "su -c 'rm -f /data/adb/modules/playintegrityfork/autopif2.sh'" 2>/dev/null || true
                echo "PIF: Rebooting phone to activate module..."
                adb reboot 2>/dev/null || true
            else
                echo "PIF: Install failed (rc=${INSTALL_RC})"
            fi
            rm -f /tmp/pif_module.zip
        else
            echo "PIF: Download failed — check network"
        fi
    fi
) &

# ── Tiny HTTP file server for screenshots ──
# Serves /share/ on ingress port so screenshots can be viewed via HA UI
mkdir -p /share/vw-relay
python3 -c "
import http.server, socketserver, os
os.chdir('/share')
handler = http.server.SimpleHTTPRequestHandler
with socketserver.TCPServer(('0.0.0.0', 8099), handler) as s:
    s.serve_forever()
" &
echo "File server: listening on :8099 (serves /share/)"

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
export PYTHONUNBUFFERED=1

# Build relay command args
CMD="/opt/venv/bin/python3 -u /opt/vw_token_relay.py"
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
        adb shell "su -c 'input swipe 540 1800 540 800 300'" 2>/dev/null || true
        sleep 1
    fi
}

ensure_phone_ready() {
    # Reset ADB server to re-detect USB devices after container restart
    echo "Resetting ADB server..."
    adb kill-server 2>/dev/null || true
    sleep 2
    adb start-server 2>/dev/null || true
    sleep 2

    # Wait for ADB device (with 120s timeout)
    echo "Waiting for USB device..."
    echo "ADB devices output: $(adb devices 2>&1)"
    echo "USB bus contents: $(ls /dev/bus/usb/002/ 2>/dev/null || echo 'no bus 002')"
    USB_WAIT=0
    USB_TIMEOUT=120
    while ! adb devices 2>/dev/null | grep -q "device$"; do
        sleep 5
        USB_WAIT=$((USB_WAIT + 5))
        if [ "$((USB_WAIT % 30))" -eq 0 ]; then
            echo "ADB wait ${USB_WAIT}s: $(adb devices 2>&1 | tail -1)"
        fi
        if [ "${USB_WAIT}" -ge "${USB_TIMEOUT}" ]; then
            echo "WARNING: No USB device after ${USB_TIMEOUT}s — starting relay without phone"
            echo "Final ADB state: $(adb devices 2>&1)"
            return 1
        fi
    done
    DEVICE=$(adb devices | grep "device$" | head -1 | awk '{print $1}')
    echo "Found ADB device: ${DEVICE}"

    # Persist ADB key on phone to prevent future "unauthorized" state
    if [ -f "${DATA_ANDROID}/adbkey.pub" ]; then
        adb push "${DATA_ANDROID}/adbkey.pub" /data/local/tmp/adbkey.pub 2>/dev/null && \
        adb shell "su -c 'cat /data/local/tmp/adbkey.pub >> /data/misc/adb/adb_keys && sort -u -o /data/misc/adb/adb_keys /data/misc/adb/adb_keys && chmod 640 /data/misc/adb/adb_keys && chown system:shell /data/misc/adb/adb_keys'" 2>/dev/null && \
        echo "ADB key persisted on phone (will survive reboots)" || \
        echo "ADB key persist failed (non-fatal)"
    fi

    # Force-restart frida-server (don't trust stale PIDs after phone reboot)
    echo "Starting frida-server on phone..."
    adb shell "su -c 'killall frida-server'" 2>/dev/null || true
    sleep 1
    adb shell "su -c '/data/local/tmp/frida-server -D &'" 2>/dev/null || true
    sleep 3

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
        # Exponential backoff: 10, 20, 40, 80, 120 (cap) — POSIX sh compatible
        RESTART_DELAY=$((RESTART_DELAY * 2))
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
