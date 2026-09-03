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
VNC_ENABLED=$(jq -r '.vnc_enabled // true' "$OPTIONS")
VNC_PASSWORD=$(jq -r '.vnc_password // empty' "$OPTIONS")

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

# Symlink ~/.android → /data/.android FIRST (ADB's working copy)
rm -rf /root/.android 2>/dev/null || true
ln -sf "${DATA_ANDROID}" /root/.android

# Restore: if key exists in /share but not /data (post-uninstall reinstall or slug change)
if [ ! -f "${DATA_ANDROID}/adbkey" ] && [ -f "${SHARE_ANDROID}/adbkey" ]; then
    echo "Restoring ADB key from /share backup (survived uninstall/slug change)..."
    cp "${SHARE_ANDROID}/adbkey" "${DATA_ANDROID}/adbkey"
    cp "${SHARE_ANDROID}/adbkey.pub" "${DATA_ANDROID}/adbkey.pub" 2>/dev/null || true
    chmod 600 "${DATA_ANDROID}/adbkey" 2>/dev/null || true
fi

if [ -f "${DATA_ANDROID}/adbkey" ]; then
    echo "ADB key ready (fingerprint: $(awk '{print $NF}' "${DATA_ANDROID}/adbkey.pub" 2>/dev/null || echo 'n/a'))"
    # Ensure backup copy is current
    cp "${DATA_ANDROID}/adbkey" "${SHARE_ANDROID}/adbkey" 2>/dev/null || true
    cp "${DATA_ANDROID}/adbkey.pub" "${SHARE_ANDROID}/adbkey.pub" 2>/dev/null || true
else
    echo "No ADB key found (share=${SHARE_ANDROID}/adbkey exists=$([ -f "${SHARE_ANDROID}/adbkey" ] && echo yes || echo no))"
    echo "Key will be generated on first ADB use and backed up to /share/.vw-relay/"
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
echo "  VNC: ${VNC_ENABLED} (port 5900)"
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

# ── VNC Server (droidVNC-NG) ──
VNC_PKG="net.christianbeier.droidvnc_ng"
VNC_APK_CACHE="/share/.vw-relay/droidvnc-ng.apk"
VNC_ACCESS_KEY="vwrelay_vnc_local"

setup_vnc() {
    if [ "${VNC_ENABLED}" != "true" ]; then
        echo "VNC: Disabled in config"
        return 0
    fi

    echo "VNC: Setting up droidVNC-NG..."

    # 1) Install or update APK — check version, force update if < 2.1.0
    vnc_install_if_needed

    # 2) Set up accessibility service and wait for it to connect
    VNC_A11Y_CONNECTED=false
    vnc_setup_accessibility

    # 3) If accessibility didn't connect, nuclear option: full uninstall + reinstall
    if [ "${VNC_A11Y_CONNECTED}" = "false" ]; then
        echo "VNC: ═══ RECOVERY: Full uninstall/reinstall to fix damaged accessibility binding ═══"
        adb shell "am force-stop ${VNC_PKG}" 2>/dev/null
        sleep 1
        # Disable accessibility before uninstall
        adb shell settings put secure enabled_accessibility_services "" 2>/dev/null
        adb shell settings put secure accessibility_enabled 0 2>/dev/null
        sleep 1
        # Full uninstall
        echo "VNC: Uninstalling ${VNC_PKG}..."
        adb shell "pm uninstall ${VNC_PKG}" 2>&1
        sleep 3
        # Reinstall from cache
        if [ -f "${VNC_APK_CACHE}" ]; then
            echo "VNC: Reinstalling from cache..."
            adb install "${VNC_APK_CACHE}" 2>&1
            sleep 2
        else
            echo "VNC: No cached APK — downloading..."
            vnc_download_apk || return 1
            adb install "${VNC_APK_CACHE}" 2>&1
            sleep 2
        fi
        VNC_INSTALLED_VER=$(adb shell "dumpsys package ${VNC_PKG}" 2>/dev/null | grep "versionName" | head -1 | sed 's/.*versionName=//' | tr -d '[:space:]')
        echo "VNC: Reinstalled version: ${VNC_INSTALLED_VER}"
        # Retry accessibility setup on clean install
        vnc_setup_accessibility
    fi

    # 4) Grant ALL permissions
    vnc_grant_permissions

    # 5) Deploy config via SharedPreferences
    vnc_deploy_config

    # 6) Wake screen
    wake_screen

    # 7) Start VNC server — always use fallback screen capture to skip
    #    MediaProjection consent (Step 4). If accessibility isn't truly connected,
    #    screen capture will fail but the VNC TCP server should still start.
    VNC_USE_FALLBACK=true
    echo "VNC: Using fallback screen capture mode (a11y=${VNC_A11Y_CONNECTED})"
    start_vnc_server

    # 8) Wait for VNC to finish its multi-step permission flow
    sleep 5

    # 10) Verify VNC is actually listening on phone
    verify_vnc_listening

    # 11) Set up port forwarding: phone:5900 → container:0.0.0.0:5900
    setup_vnc_forwarding
}

vnc_download_apk() {
    mkdir -p "$(dirname "${VNC_APK_CACHE}")"
    echo "VNC: Downloading latest release from GitHub..."
    /opt/venv/bin/python3 -c "
import urllib.request, json, sys
try:
    data = json.loads(urllib.request.urlopen(
        'https://api.github.com/repos/bk138/droidVNC-NG/releases/latest',
        timeout=30).read())
    apks = [a for a in data['assets'] if a['name'].endswith('.apk')]
    if not apks:
        sys.exit('No APK in release assets')
    urllib.request.urlretrieve(apks[0]['browser_download_url'], '${VNC_APK_CACHE}')
    print('VNC: Downloaded ' + apks[0]['name'])
except Exception as e:
    sys.exit('VNC: Download failed: ' + str(e))
" 2>&1
    if [ $? -ne 0 ]; then
        echo "VNC: APK download failed"
        rm -f "${VNC_APK_CACHE}"
        return 1
    fi
    return 0
}

vnc_install_if_needed() {
    VNC_INSTALLED_VER=$(adb shell "dumpsys package ${VNC_PKG}" 2>/dev/null | grep "versionName" | head -1 | sed 's/.*versionName=//' | tr -d '[:space:]')
    echo "VNC: Installed version: ${VNC_INSTALLED_VER:-not installed}"

    VNC_NEED_INSTALL=false
    if [ -z "${VNC_INSTALLED_VER}" ]; then
        VNC_NEED_INSTALL=true
    else
        VNC_MAJOR=$(echo "${VNC_INSTALLED_VER}" | cut -d. -f1)
        VNC_MINOR=$(echo "${VNC_INSTALLED_VER}" | cut -d. -f2)
        if [ "${VNC_MAJOR}" -lt 2 ] 2>/dev/null || { [ "${VNC_MAJOR}" -eq 2 ] && [ "${VNC_MINOR}" -lt 1 ]; } 2>/dev/null; then
            echo "VNC: Version ${VNC_INSTALLED_VER} too old — need >= 2.1.0"
            VNC_NEED_INSTALL=true
            rm -f "${VNC_APK_CACHE}"
        fi
    fi

    if [ "${VNC_NEED_INSTALL}" = "true" ]; then
        echo "VNC: Installing/updating droidVNC-NG..."
        if [ ! -f "${VNC_APK_CACHE}" ]; then
            vnc_download_apk || return 1
        fi
        if [ -n "${VNC_INSTALLED_VER}" ]; then
            echo "VNC: Removing old version..."
            adb shell "pm uninstall ${VNC_PKG}" 2>/dev/null || true
            sleep 2
        fi
        adb install "${VNC_APK_CACHE}" 2>&1
        if [ $? -ne 0 ]; then
            echo "VNC: Install failed"
            rm -f "${VNC_APK_CACHE}"
            return 1
        fi
        VNC_INSTALLED_VER=$(adb shell "dumpsys package ${VNC_PKG}" 2>/dev/null | grep "versionName" | head -1 | sed 's/.*versionName=//' | tr -d '[:space:]')
        echo "VNC: Installed version: ${VNC_INSTALLED_VER}"
    else
        echo "VNC: Stopping app for clean restart..."
        adb shell "am force-stop ${VNC_PKG}" 2>/dev/null
        sleep 1
    fi
}

vnc_setup_accessibility() {
    echo "VNC: Setting up accessibility input service..."

    # Toggle off then on
    echo "VNC: Toggling accessibility service off/on..."
    adb shell settings put secure enabled_accessibility_services "" 2>/dev/null
    adb shell settings put secure accessibility_enabled 0 2>/dev/null
    sleep 2

    # Re-enable
    adb shell settings put secure enabled_accessibility_services "${VNC_PKG}/.InputService" 2>/dev/null
    adb shell settings put secure accessibility_enabled 1 2>/dev/null
    sleep 3

    # Launch app so Android has the service process to bind to
    echo "VNC: Launching app to trigger accessibility binding..."
    adb shell "am start -n ${VNC_PKG}/.MainActivity" 2>&1
    sleep 5

    # Press Home if InputRequestActivity appeared
    FOREGROUND=$(adb shell "dumpsys activity activities" 2>/dev/null | grep "mResumedActivity" | head -1)
    if echo "${FOREGROUND}" | grep -q "InputRequestActivity"; then
        echo "VNC: Dismissing InputRequestActivity..."
        adb shell "input keyevent KEYCODE_HOME" 2>/dev/null
        sleep 1
    fi

    # Wait for InputService to connect (10 attempts, 30s)
    # Check for EITHER mIsConnected=true (newer Android) OR the service
    # being listed in "Bound services" (Android 11 format)
    echo "VNC: Waiting for accessibility service to connect..."
    for i in 1 2 3 4 5 6 7 8 9 10; do
        A11Y_DUMP=$(adb shell "dumpsys accessibility" 2>/dev/null)
        A11Y_VNC=$(echo "${A11Y_DUMP}" | grep -A15 "droidvnc_ng")
        # Method 1: explicit mIsConnected field (Android 12+)
        if echo "${A11Y_VNC}" | grep -qi "mIsConnected=true"; then
            echo "VNC: InputService connected (mIsConnected=true)!"
            VNC_A11Y_CONNECTED=true
            return 0
        fi
        # Method 2: service in "Bound services" but NOT in "Binding services" or "Crashed services" (Android 11)
        if echo "${A11Y_VNC}" | grep -q "Bound services:.*droidVNC"; then
            A11Y_BINDING=$(echo "${A11Y_VNC}" | grep "Binding services:" | head -1)
            A11Y_CRASHED=$(echo "${A11Y_VNC}" | grep "Crashed services:" | head -1)
            if ! echo "${A11Y_BINDING}" | grep -q "droidvnc" && ! echo "${A11Y_CRASHED}" | grep -q "droidvnc"; then
                echo "VNC: InputService connected (in Bound services)!"
                VNC_A11Y_CONNECTED=true
                return 0
            fi
        fi
        echo "VNC: Waiting for bind... (${i}/10)"
        sleep 3
    done

    echo "VNC: WARNING — InputService did not connect after 30s"
    echo "VNC: Accessibility state:"
    adb shell "dumpsys accessibility" 2>/dev/null | grep -A15 "droidvnc_ng" | head -20
}

vnc_grant_permissions() {
    echo "VNC: Granting permissions..."
    adb shell "su -c 'pm grant ${VNC_PKG} android.permission.WRITE_EXTERNAL_STORAGE'" 2>/dev/null || true
    adb shell "su -c 'pm grant ${VNC_PKG} android.permission.READ_EXTERNAL_STORAGE'" 2>/dev/null || true
    adb shell "su -c 'appops set ${VNC_PKG} MANAGE_EXTERNAL_STORAGE allow'" 2>/dev/null || true
    adb shell "su -c 'appops set ${VNC_PKG} android:legacy_storage allow'" 2>/dev/null || true
    adb shell "su -c 'appops set ${VNC_PKG} PROJECT_MEDIA allow'" 2>/dev/null
    adb shell "su -c 'pm grant ${VNC_PKG} android.permission.FOREGROUND_SERVICE'" 2>/dev/null || true
    adb shell "su -c 'pm grant ${VNC_PKG} android.permission.FOREGROUND_SERVICE_MEDIA_PROJECTION'" 2>/dev/null || true
    adb shell "su -c 'pm grant ${VNC_PKG} android.permission.SYSTEM_ALERT_WINDOW'" 2>/dev/null || true
    adb shell "su -c 'appops set ${VNC_PKG} SYSTEM_ALERT_WINDOW allow'" 2>/dev/null || true
}

vnc_deploy_config() {
    echo "VNC: Writing config via SharedPreferences..."
    VNC_APP_UID=$(adb shell "su -c 'stat -c %u /data/data/${VNC_PKG}'" 2>/dev/null || echo "")
    echo "VNC: App UID=${VNC_APP_UID}"

    VNC_PREFS_DIR="/data/data/${VNC_PKG}/shared_prefs"
    adb shell "su -c 'mkdir -p ${VNC_PREFS_DIR}'" 2>/dev/null
    VNC_PASS_PREF=""
    if [ -n "${VNC_PASSWORD}" ]; then
        VNC_PASS_PREF="    <string name=\"settings_password\">${VNC_PASSWORD}</string>"
    fi
    cat > /tmp/vnc_prefs.xml << PREFSEOF
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <int name="settings_port" value="5900" />
    <string name="settings_access_key">${VNC_ACCESS_KEY}</string>
    <boolean name="settings_start_on_boot" value="true" />
    <int name="settings_start_on_boot_delay" value="5" />
    <boolean name="settings_view_only" value="false" />
    <boolean name="settings_file_transfer" value="false" />
    <float name="settings_scaling" value="0.5" />
${VNC_PASS_PREF}
</map>
PREFSEOF
    adb push /tmp/vnc_prefs.xml /data/local/tmp/vnc_prefs.xml 2>/dev/null
    adb shell "su -c 'cp /data/local/tmp/vnc_prefs.xml ${VNC_PREFS_DIR}/${VNC_PKG}_preferences.xml'" 2>/dev/null
    if [ -n "${VNC_APP_UID}" ]; then
        adb shell "su -c 'chown ${VNC_APP_UID}:${VNC_APP_UID} ${VNC_PREFS_DIR}/${VNC_PKG}_preferences.xml'" 2>/dev/null
        adb shell "su -c 'chmod 660 ${VNC_PREFS_DIR}/${VNC_PKG}_preferences.xml'" 2>/dev/null
    fi
    echo "VNC: SharedPreferences written"

    # Also place defaults.json in internal data dir (not FUSE-gated)
    VNC_DEFAULTS="/tmp/vnc_defaults.json"
    VNC_PASS_JSON=""
    if [ -n "${VNC_PASSWORD}" ]; then
        VNC_PASS_JSON="\"password\": \"${VNC_PASSWORD}\","
    fi
    cat > "${VNC_DEFAULTS}" << VNCEOF
{
    "port": 5900,
    ${VNC_PASS_JSON}
    "accessKey": "${VNC_ACCESS_KEY}",
    "startOnBoot": true,
    "startOnBootDelay": 5,
    "viewOnly": false,
    "fileTransfer": false,
    "scaling": 0.5
}
VNCEOF
    adb push "${VNC_DEFAULTS}" /data/local/tmp/vnc_defaults.json 2>/dev/null
    adb shell "su -c 'mkdir -p /data/data/${VNC_PKG}/files'" 2>/dev/null
    adb shell "su -c 'cp /data/local/tmp/vnc_defaults.json /data/data/${VNC_PKG}/files/defaults.json'" 2>/dev/null
    if [ -n "${VNC_APP_UID}" ]; then
        adb shell "su -c 'chown ${VNC_APP_UID}:${VNC_APP_UID} /data/data/${VNC_PKG}/files/defaults.json'" 2>/dev/null
    fi
    rm -f "${VNC_DEFAULTS}" /tmp/vnc_prefs.xml
}

start_vnc_server() {
    echo "VNC: Starting server..."
    # Force stop first to ensure clean state
    adb shell "am force-stop ${VNC_PKG}" 2>/dev/null
    sleep 2

    # Launch main activity so the app initializes
    echo "VNC: Launching main activity..."
    adb shell "am start -n ${VNC_PKG}/.MainActivity" 2>&1
    sleep 5

    # Start the foreground service — triggers Step 1 of droidVNC-NG's
    # multi-step permission flow: persist intent → InputRequest (Step 2) →
    # WriteStorage/Notification (Step 3) → MediaProjection (Step 4) → VNC starts
    VNC_START_CMD="am start-foreground-service"
    VNC_START_CMD="${VNC_START_CMD} -n ${VNC_PKG}/.MainService"
    VNC_START_CMD="${VNC_START_CMD} -a ${VNC_PKG}.ACTION_START"
    VNC_START_CMD="${VNC_START_CMD} --es ${VNC_PKG}.EXTRA_ACCESS_KEY ${VNC_ACCESS_KEY}"
    VNC_START_CMD="${VNC_START_CMD} --ei ${VNC_PKG}.EXTRA_PORT 5900"
    VNC_START_CMD="${VNC_START_CMD} --ef ${VNC_PKG}.EXTRA_SCALING 0.5"
    VNC_START_CMD="${VNC_START_CMD} --ez ${VNC_PKG}.EXTRA_FALLBACK_SCREEN_CAPTURE true"
    if [ -n "${VNC_PASSWORD}" ]; then
        VNC_START_CMD="${VNC_START_CMD} --es ${VNC_PKG}.EXTRA_PASSWORD ${VNC_PASSWORD}"
    fi
    echo "VNC: Sending ACTION_START (fallback capture mode)..."
    adb shell "${VNC_START_CMD}" 2>&1
    sleep 3

    # droidVNC-NG has a multi-step permission flow. Each step launches an Activity
    # that blocks until the user acts. On a headless phone, we bypass each step by
    # detecting the blocking activity and sending the result intent directly.
    #
    # Flow: ACTION_START (Step 1) → InputRequestActivity (Step 2) →
    #        WriteStorageRequestActivity (Step 3, Android <13) → VNC starts
    #        (Step 4 MediaProjection is SKIPPED because EXTRA_FALLBACK_SCREEN_CAPTURE=true)
    vnc_bypass_permission_flow
}

vnc_bypass_permission_flow() {
    echo "VNC: Checking for blocking permission activities..."

    for round in 1 2 3 4 5 6; do
        FOREGROUND=$(adb shell "dumpsys activity activities" 2>/dev/null | grep "mResumedActivity" | head -1)
        echo "VNC: Round ${round} foreground: ${FOREGROUND}"

        if echo "${FOREGROUND}" | grep -q "InputRequestActivity"; then
            echo "VNC: Bypassing InputRequestActivity (Step 2 — accessibility)..."
            adb shell "input keyevent KEYCODE_HOME" 2>/dev/null
            sleep 1
            # Send ACTION_HANDLE_INPUT_RESULT directly to MainService
            adb shell "am start-foreground-service \
                -n ${VNC_PKG}/.MainService \
                -a action_handle_a11y_result \
                --ez result_a11y true \
                --es ${VNC_PKG}.EXTRA_ACCESS_KEY ${VNC_ACCESS_KEY}" 2>&1
            echo "VNC: Sent input result — proceeding to Step 3"
            sleep 3
            continue

        elif echo "${FOREGROUND}" | grep -q "WriteStorageRequestActivity"; then
            echo "VNC: Bypassing WriteStorageRequestActivity (Step 3 — storage)..."
            adb shell "input keyevent KEYCODE_HOME" 2>/dev/null
            sleep 1
            # Send ACTION_HANDLE_WRITE_STORAGE_RESULT directly
            adb shell "am start-foreground-service \
                -n ${VNC_PKG}/.MainService \
                -a action_handle_write_storage_result \
                --es ${VNC_PKG}.EXTRA_ACCESS_KEY ${VNC_ACCESS_KEY}" 2>&1
            echo "VNC: Sent storage result — proceeding to VNC start"
            sleep 3
            continue

        elif echo "${FOREGROUND}" | grep -q "NotificationRequestActivity"; then
            echo "VNC: Bypassing NotificationRequestActivity (Step 3 — notification)..."
            adb shell "input keyevent KEYCODE_HOME" 2>/dev/null
            sleep 1
            adb shell "am start-foreground-service \
                -n ${VNC_PKG}/.MainService \
                -a action_handle_notification_result \
                --es ${VNC_PKG}.EXTRA_ACCESS_KEY ${VNC_ACCESS_KEY}" 2>&1
            echo "VNC: Sent notification result"
            sleep 3
            continue

        elif echo "${FOREGROUND}" | grep -q "MediaProjectionRequestActivity"; then
            echo "VNC: Bypassing MediaProjectionRequestActivity (Step 4 — should not happen with fallback)..."
            adb shell "input keyevent KEYCODE_HOME" 2>/dev/null
            sleep 1
            # This shouldn't happen with EXTRA_FALLBACK_SCREEN_CAPTURE=true,
            # but if it does, send result code 0 (no projection — use fallback)
            adb shell "am start-foreground-service \
                -n ${VNC_PKG}/.MainService \
                -a action_handle_media_projection_result \
                --ei result_code_media_projection_request 0 \
                --es ${VNC_PKG}.EXTRA_ACCESS_KEY ${VNC_ACCESS_KEY}" 2>&1
            sleep 3
            continue
        fi

        # No blocking activity — flow has progressed past permission checks
        echo "VNC: No blocking activity detected — permission flow complete"
        break
    done
}

accept_media_projection() {
    # On Android 10+, MediaProjection shows a consent dialog.
    # Multiple strategies to detect and accept it.
    echo "VNC: Checking for MediaProjection consent dialog..."
    sleep 5

    for attempt in 1 2 3 4 5 6 7 8; do
        # Strategy 1: Check dumpsys window for the consent dialog
        FOCUS=$(adb shell "dumpsys window windows" 2>/dev/null | grep -i "mCurrentFocus\|mFocusedApp" | head -2)
        echo "VNC: Attempt ${attempt} — focus: ${FOCUS}"

        if echo "${FOCUS}" | grep -qi "MediaProjection\|GrantPermission\|permission\|AlertDialog\|chooser"; then
            echo "VNC: Consent dialog detected via window focus — accepting..."
            # Try Enter key first (most reliable for dialogs)
            adb shell "input keyevent KEYCODE_TAB" 2>/dev/null
            sleep 0.5
            adb shell "input keyevent KEYCODE_TAB" 2>/dev/null
            sleep 0.5
            adb shell "input keyevent KEYCODE_ENTER" 2>/dev/null
            sleep 2
            echo "VNC: Sent Enter key to accept dialog"
            return 0
        fi

        # Strategy 2: Try uiautomator dump
        DUMP=$(adb shell "uiautomator dump /dev/tty" 2>/dev/null || echo "")
        if [ ${#DUMP} -gt 100 ]; then
            echo "VNC: UI dump: ${#DUMP} chars"
            if echo "${DUMP}" | grep -qi "start now\|Start recording\|allow\|start capturing\|screen capture\|will start capturing"; then
                echo "VNC: Found consent dialog in UI dump — tapping..."
                # Try to find and tap the accept button
                BOUNDS=""
                for BTN_TEXT in "Start now" "START NOW" "start now" "Allow" "ALLOW" "Start" "OK"; do
                    BOUNDS=$(echo "${DUMP}" | grep -oi "text=\"${BTN_TEXT}\"[^/]*bounds=\"\[[0-9]*,[0-9]*\]\[[0-9]*,[0-9]*\]\"" | head -1 | grep -o 'bounds="\[[0-9]*,[0-9]*\]\[[0-9]*,[0-9]*\]"')
                    [ -n "${BOUNDS}" ] && break
                done
                if [ -n "${BOUNDS}" ]; then
                    X1=$(echo "${BOUNDS}" | sed 's/bounds="\[\([0-9]*\),.*/\1/')
                    Y1=$(echo "${BOUNDS}" | sed 's/bounds="\[[0-9]*,\([0-9]*\)\].*/\1/')
                    X2=$(echo "${BOUNDS}" | sed 's/.*\]\[\([0-9]*\),.*/\1/')
                    Y2=$(echo "${BOUNDS}" | sed 's/.*\]\[[0-9]*,\([0-9]*\)\].*/\1/')
                    CX=$(( (X1 + X2) / 2 ))
                    CY=$(( (Y1 + Y2) / 2 ))
                    adb shell "input tap ${CX} ${CY}" 2>/dev/null
                    echo "VNC: Tapped at ${CX},${CY}"
                else
                    adb shell "input keyevent KEYCODE_ENTER" 2>/dev/null
                fi
                sleep 3
                return 0
            fi
        else
            echo "VNC: UI dump too short (${#DUMP} chars) — trying blind accept"
            # If uiautomator consistently fails, try blind keypress
            if [ "${attempt}" -ge 3 ]; then
                adb shell "input keyevent KEYCODE_ENTER" 2>/dev/null
                sleep 1
                # Also try tap at common "Start now" button position on Moto G Pure (720x1440)
                adb shell "input tap 540 1200" 2>/dev/null
                sleep 1
            fi
        fi
        sleep 3
    done
    echo "VNC: No MediaProjection dialog detected after 8 attempts"
}

verify_vnc_listening() {
    echo "VNC: Verifying server is listening on phone..."
    sleep 5
    # Check if port 5900 is open on the phone
    LISTENING=$(adb shell "su -c 'ss -tlnp'" 2>/dev/null | grep 5900 || \
                adb shell "su -c 'netstat -tlnp'" 2>/dev/null | grep 5900 || echo "")
    if [ -n "${LISTENING}" ]; then
        echo "VNC: ✓ Confirmed — phone listening on port 5900"
        echo "VNC: ${LISTENING}"
        return 0
    fi

    echo "VNC: ✗ Port 5900 NOT open on phone!"

    # Full diagnostic dump
    echo "VNC: ═══ DIAGNOSTICS ═══"
    VNC_PID=$(adb shell pidof "${VNC_PKG}" 2>/dev/null || echo "")
    if [ -n "${VNC_PID}" ]; then
        echo "VNC: App running as PID ${VNC_PID}"
        echo "VNC: --- Full logcat (last 50 lines) ---"
        adb shell "logcat -d -t 50 --pid=${VNC_PID}" 2>&1 | tail -50
    else
        echo "VNC: App NOT running (crashed?)"
        echo "VNC: --- Recent crash/VNC logs ---"
        adb shell "logcat -d -t 100" 2>&1 | grep -i "droidvnc\|MainService\|InputService\|AndroidRuntime\|FATAL\|NullPointer\|died\|crash" | tail -30
    fi
    echo "VNC: --- Service state ---"
    adb shell "dumpsys activity services ${VNC_PKG}" 2>/dev/null | head -20
    echo "VNC: --- All listening ports ---"
    adb shell "su -c 'ss -tlnp'" 2>/dev/null | head -15
    echo "VNC: ═══ END DIAGNOSTICS ═══"

    # Retry: re-grant and restart
    echo "VNC: Retrying..."
    adb shell "su -c 'appops set ${VNC_PKG} PROJECT_MEDIA allow'" 2>/dev/null
    adb shell "am force-stop ${VNC_PKG}" 2>/dev/null || true
    sleep 2
    start_vnc_server

    if [ "${VNC_USE_FALLBACK}" = "false" ]; then
        accept_media_projection
    fi
    sleep 5

    LISTENING2=$(adb shell "su -c 'ss -tlnp'" 2>/dev/null | grep 5900 || echo "")
    if [ -n "${LISTENING2}" ]; then
        echo "VNC: ✓ Confirmed after retry — phone listening on port 5900"
    else
        echo "VNC: ✗ Still not listening after retry"
        VNC_PID2=$(adb shell pidof "${VNC_PKG}" 2>/dev/null || echo "")
        if [ -n "${VNC_PID2}" ]; then
            echo "VNC: Post-retry logcat (PID ${VNC_PID2}):"
            adb shell "logcat -d -t 30 --pid=${VNC_PID2}" 2>&1 | tail -30
        fi
    fi
}

setup_vnc_forwarding() {
    # ADB forward binds to localhost only; socat bridges to 0.0.0.0
    echo "VNC: Setting up port forwarding..."
    adb forward tcp:15900 tcp:5900 2>/dev/null

    # Kill any existing socat for VNC
    pkill -f "socat.*TCP-LISTEN:5900" 2>/dev/null || true
    sleep 1

    # Bridge: external:5900 → localhost:15900 (ADB forward) → phone:5900
    socat TCP-LISTEN:5900,fork,reuseaddr,bind=0.0.0.0 TCP:127.0.0.1:15900 &
    echo "VNC: Port forwarding active — connect to port 5900"
}

ensure_vnc() {
    if [ "${VNC_ENABLED}" != "true" ]; then
        return 0
    fi

    # Check if socat bridge is still running
    if ! pgrep -f "socat.*TCP-LISTEN:5900" > /dev/null 2>&1; then
        echo "VNC: socat bridge died — restarting forwarding..."
        setup_vnc_forwarding
    fi

    # Check if VNC service is running on phone
    if ! adb shell "dumpsys activity services ${VNC_PKG}" 2>/dev/null | grep -q "ServiceRecord"; then
        echo "VNC: Service not running — restarting..."
        start_vnc_server
        sleep 2
        # Re-establish ADB forward (may have been lost)
        adb forward tcp:15900 tcp:5900 2>/dev/null
    fi
}

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

    # Set up VNC server (droidVNC-NG) if enabled
    setup_vnc
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
