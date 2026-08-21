#!/bin/sh
# Play Integrity fingerprint auto-updater
# Detects the PIF module on the phone, runs its built-in autopif script
# to generate a fresh fingerprint, or downloads one from known sources.
# Called by entrypoint.sh (hourly) and vw_token_relay.py (MQTT command).
#
# Usage: update_pif.sh [--reboot]
#   --reboot  Reboot the phone after updating (needed for Zygisk reload)

REBOOT_FLAG=""
for arg in "$@"; do
    case "$arg" in
        --reboot) REBOOT_FLAG=1 ;;
    esac
done

echo "PIF: Checking Play Integrity fingerprint..."

# Ensure ADB is connected
if ! adb devices 2>/dev/null | grep -q "device$"; then
    echo "PIF: No ADB device connected, skipping"
    exit 1
fi

# ── Detect PIF module and variant ──
PIF_DIR=""
PIF_VARIANT=""
AUTOPIF_SCRIPT=""

# Check playintegrityfix (KOWX712 / chiteroman)
if adb shell "su -c 'test -d /data/adb/modules/playintegrityfix'" 2>/dev/null; then
    PIF_DIR="/data/adb/modules/playintegrityfix"
    MODULE_PROP=$(adb shell "su -c 'cat ${PIF_DIR}/module.prop'" 2>/dev/null || echo "")
    if echo "$MODULE_PROP" | grep -qi 'KOWX712'; then
        PIF_VARIANT="kowx712"
        if adb shell "su -c 'test -f ${PIF_DIR}/autopif.sh'" 2>/dev/null; then
            AUTOPIF_SCRIPT="${PIF_DIR}/autopif.sh"
        fi
    elif echo "$MODULE_PROP" | grep -qi 'osm0sis'; then
        PIF_VARIANT="osm0sis"
        AUTOPIF_SCRIPT=$(adb shell "su -c 'ls ${PIF_DIR}/autopif[0-9]*.sh 2>/dev/null | sort -V -r | head -1'" 2>/dev/null | tr -d '\r\n')
    else
        PIF_VARIANT="chiteroman"
        if adb shell "su -c 'test -f ${PIF_DIR}/action.sh'" 2>/dev/null; then
            AUTOPIF_SCRIPT="${PIF_DIR}/action.sh"
        fi
    fi
# Check playintegrityfork (osm0sis fork name)
elif adb shell "su -c 'test -d /data/adb/modules/playintegrityfork'" 2>/dev/null; then
    PIF_DIR="/data/adb/modules/playintegrityfork"
    PIF_VARIANT="osm0sis"
    AUTOPIF_SCRIPT=$(adb shell "su -c 'ls ${PIF_DIR}/autopif[0-9]*.sh 2>/dev/null | sort -V -r | head -1'" 2>/dev/null | tr -d '\r\n')
fi

if [ -z "$PIF_DIR" ]; then
    echo "PIF: No Play Integrity Fix module found on phone!"
    exit 1
fi

echo "PIF: Found module at ${PIF_DIR} (variant: ${PIF_VARIANT})"

# Snapshot current fingerprint for change detection
OLD_FP=$(adb shell "su -c 'cat ${PIF_DIR}/custom.pif.prop 2>/dev/null || cat ${PIF_DIR}/pif.json 2>/dev/null || cat /data/adb/pif.json 2>/dev/null'" 2>/dev/null | head -20 || echo "")

# ── Method 1: Run the module's built-in autopif script ──
if [ -n "$AUTOPIF_SCRIPT" ] && adb shell "su -c 'test -f ${AUTOPIF_SCRIPT}'" 2>/dev/null; then
    echo "PIF: Running built-in script: ${AUTOPIF_SCRIPT}"
    if [ "$PIF_VARIANT" = "chiteroman" ]; then
        adb shell "su -c 'sh ${AUTOPIF_SCRIPT}'" 2>&1 | sed 's/^/PIF:   /'
    else
        adb shell "su -c 'sh ${AUTOPIF_SCRIPT} -p'" 2>&1 | sed 's/^/PIF:   /'
    fi
    echo "PIF: Built-in script finished"
else
    # ── Method 2: Download pif.json from known sources ──
    echo "PIF: No autopif script available, downloading fingerprint..."

    /opt/venv/bin/python3 - <<'PYEOF'
import urllib.request, json, sys

sources = [
    ("daboynb/autojson",  "https://raw.githubusercontent.com/daboynb/autojson/main/pif.json"),
    ("vladrevers/pifsync", "https://raw.githubusercontent.com/vladrevers/pifsync/main/pif.json"),
]

for name, url in sources:
    try:
        data = urllib.request.urlopen(url, timeout=30).read()
        parsed = json.loads(data)
        with open("/tmp/pif_new.json", "wb") as f:
            f.write(data)
        fp = parsed.get("FINGERPRINT", "unknown")
        print(f"PIF:   Downloaded from {name}")
        print(f"PIF:   Fingerprint: {fp}")
        sys.exit(0)
    except Exception as e:
        print(f"PIF:   Failed {name}: {e}")

print("PIF:   All sources failed!")
sys.exit(1)
PYEOF

    if [ $? -eq 0 ] && [ -f /tmp/pif_new.json ]; then
        if [ "$PIF_VARIANT" = "osm0sis" ]; then
            TARGET_JSON="${PIF_DIR}/custom.pif.json"
        else
            TARGET_JSON="/data/adb/pif.json"
        fi

        echo "PIF: Pushing new fingerprint to ${TARGET_JSON}"
        adb push /tmp/pif_new.json /data/local/tmp/pif.json 2>/dev/null
        adb shell "su -c 'cp /data/local/tmp/pif.json ${TARGET_JSON} && chmod 644 ${TARGET_JSON}'" 2>/dev/null
    else
        echo "PIF: Download failed, cannot update"
        exit 1
    fi
fi

# Check if fingerprint actually changed
NEW_FP=$(adb shell "su -c 'cat ${PIF_DIR}/custom.pif.prop 2>/dev/null || cat ${PIF_DIR}/pif.json 2>/dev/null || cat /data/adb/pif.json 2>/dev/null'" 2>/dev/null | head -20 || echo "")

if [ "$OLD_FP" != "$NEW_FP" ]; then
    echo "PIF: Fingerprint changed — killing DroidGuard for refresh..."
    adb shell "su -c 'killall com.google.android.gms.unstable'" 2>/dev/null || true

    if [ -n "$REBOOT_FLAG" ]; then
        # ── Safe reboot with boot-loop protection ──
        # Read uptime (seconds since boot) from /proc/uptime
        UPTIME=$(adb shell "cat /proc/uptime" 2>/dev/null | awk '{printf "%d", $1}')
        if [ -z "$UPTIME" ]; then
            echo "PIF: Cannot read uptime, skipping reboot for safety"
        elif [ "$UPTIME" -lt 1800 ]; then
            echo "PIF: Phone uptime only ${UPTIME}s (<30min) — SKIPPING reboot to prevent boot loop"
        else
            echo "PIF: Phone uptime ${UPTIME}s (>30min) — safe to reboot"
            echo "PIF: Rebooting phone..."
            adb shell "su -c 'reboot'" 2>/dev/null || true
            sleep 5

            # Wait for phone to come back (up to 3 minutes)
            echo "PIF: Waiting for phone to come back online..."
            ATTEMPTS=0
            MAX_ATTEMPTS=36  # 36 * 5s = 3 min
            while [ $ATTEMPTS -lt $MAX_ATTEMPTS ]; do
                sleep 5
                ATTEMPTS=$((ATTEMPTS + 1))
                if adb devices 2>/dev/null | grep -q "device$"; then
                    # Verify su still works (phone is fully booted)
                    if adb shell "su -c 'id'" 2>/dev/null | grep -q "uid=0"; then
                        echo "PIF: Phone back online after ~$((ATTEMPTS * 5))s"
                        # Kill DroidGuard again after reboot
                        sleep 10
                        adb shell "su -c 'killall com.google.android.gms.unstable'" 2>/dev/null || true
                        break
                    fi
                fi
            done

            if [ $ATTEMPTS -ge $MAX_ATTEMPTS ]; then
                echo "PIF: WARNING — phone did not come back after 3 min!"
            fi
        fi
    else
        echo "PIF: Reboot not requested (pass --reboot to enable)"
    fi
else
    echo "PIF: Fingerprint unchanged, no reboot needed"
    # Still kill DroidGuard as a lighter refresh
    adb shell "su -c 'killall com.google.android.gms.unstable'" 2>/dev/null || true
fi

echo "PIF: Update complete"
exit 0
