#!/usr/bin/env python3
"""
VW myVW Token Relay — Frida + MQTT bridge for Home Assistant.

Hooks the VW app's OkHttp3 stack via Frida to capture OAuth tokens,
then publishes them to MQTT for HA consumption. Also accepts MQTT
commands to make direct API calls using the captured tokens.

Play Integrity is enforced on the token endpoint, so tokens CANNOT be
refreshed directly. The app handles PI attestation + refresh; we just
capture the fresh tokens each time it refreshes.

Architecture:
  Phone (VW app + Frida) --USB--> This script --MQTT--> Home Assistant

Requirements (on the machine with USB to phone):
    pip3 install frida==16.5.9 frida-tools==13.6.1 paho-mqtt

Usage:
    python3 vw_token_relay.py --mqtt-host <HA_IP> [--mqtt-port 1883]
"""

import argparse
import hashlib
import json
import logging
import os
import re
import signal
import struct
import subprocess
import sys
import threading
import time
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from datetime import datetime, timedelta
from urllib.request import Request, urlopen
from urllib.error import HTTPError

try:
    import frida
except ImportError:
    print("Install frida: pip3 install frida==16.5.9 frida-tools==13.6.1")
    sys.exit(1)

try:
    import paho.mqtt.client as mqtt
except ImportError:
    print("Install paho-mqtt: pip3 install paho-mqtt")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("vw-relay")

# ── Config (env vars override for HA add-on mode) ─────────────────
VW_PACKAGE = os.environ.get("VW_PACKAGE", "com.vw.carnet.releaseca")
MQTT_TOPIC_PREFIX = "vw"
BASE_URL = os.environ.get("BASE_URL", "https://b-h-s.spr.ca00.p.con-veh.net")

# Respect LOG_LEVEL env var from add-on config
_log_level = os.environ.get("LOG_LEVEL", "info").upper()
if _log_level in ("DEBUG", "INFO", "WARNING", "ERROR"):
    logging.getLogger().setLevel(getattr(logging, _log_level))

# Headers the VW API expects on every request
VW_API_HEADERS = {
    "x-user-agent": "mobile-android",
    "x-app-uuid": "ff11f6c3-d7b8-4a93-aac7-475783fab95b",
    "x-user-country": "CA",
    "x-app-version": "2026.6.12-9207",
    "x-app-device-model": "moto g pure",
    "x-app-device-os": "31",
    "x-user-locale": "en-CA",
    "Content-Type": "application/json;charset=UTF-8",
}

# ── Frida JS payload ───────────────────────────────────────────────
FRIDA_SCRIPT = r"""
'use strict';

Java.perform(function () {
    var Bridge = Java.use('okhttp3.internal.http.BridgeInterceptor');
    var JLong  = Java.use('java.lang.Long');
    var PEEK   = JLong.parseLong('131072');

    // Lazily resolve okio.Buffer — may be obfuscated in some builds
    var BufferClass = null;
    try { BufferClass = Java.use('okio.Buffer'); } catch(e) {}
    // Try shaded/relocated okio paths
    if (!BufferClass) try { BufferClass = Java.use('okhttp3.internal.okio.Buffer'); } catch(e) {}
    if (!BufferClass) try { BufferClass = Java.use('o.Buffer'); } catch(e) {}

    // Known API path prefixes
    var API_PATHS = [
        '/oidc/',            // OAuth token exchange
        '/account/v1/',      // garage / vehicle list
        '/rrs/v1/',          // privileges / capabilities
        '/rvs/v1/',          // vehicle status (doors, windows, lights, odometer, location, power)
        '/ev/v1/',           // EV climate + charging
        '/lockunlock/v1/',   // lock/unlock commands + status
        '/honkandflash/',    // honk and flash
        '/fas/v1/',          // features
        '/climatisation/',   // climatisation commands
        '/charging/',        // charging commands
        '/mps/v1/',          // legacy commands (remote start?)
        '/ss/v1/',           // SPIN / session
        '/pairing/',         // device pairing (remote start)
        '/rst/v1/',          // remote engine start
        '/res/v1/',          // remote engine start (legacy)
        '/vhs/',             // vehicle health
        '/history/v1/',      // remote operation history
        '/pair/v1/',         // device pairing
    ];

    // Domains we care about (VW backend)
    var VW_DOMAINS = ['con-veh.net', 'vwgroup.io', 'volkswagen'];

    function isVwDomain(u) {
        for (var i = 0; i < VW_DOMAINS.length; i++) {
            if (u.indexOf(VW_DOMAINS[i]) !== -1) return true;
        }
        return false;
    }

    function isApiUrl(u) {
        for (var i = 0; i < API_PATHS.length; i++) {
            if (u.indexOf(API_PATHS[i]) !== -1) return true;
        }
        return false;
    }

    function getRequestBody(req) {
        try {
            var body = req.body();
            if (body === null) return null;
            if (BufferClass) {
                var buffer = BufferClass.$new();
                body.writeTo(buffer);
                return buffer.readUtf8();
            }
            // Fallback: just report content type and length
            var ct = body.contentType();
            var cl = body.contentLength();
            return '(body: type=' + ct + ', len=' + cl + ', okio.Buffer not available)';
        } catch (e) {
            return '(error reading body: ' + e + ')';
        }
    }

    function getHeaders(hdrs) {
        var result = {};
        for (var i = 0; i < hdrs.size(); i++) {
            result[hdrs.name(i)] = hdrs.value(i);
        }
        return result;
    }

    Bridge.intercept.implementation = function (chain) {
        var req  = chain.request();
        var url  = req.url().toString();
        var method = req.method();
        var resp = this.intercept(chain);

        // ── Capture Authorization headers → fresh access tokens ──
        var hdrs = req.headers();
        for (var i = 0; i < hdrs.size(); i++) {
            if (hdrs.name(i) === 'Authorization') {
                var val = hdrs.value(i);
                if (val.length > 50) {
                    send({ type: 'auth_header', url: url, token: val.substring(7) });
                }
                break;
            }
        }

        // ── Capture OIDC token responses (access + refresh tokens) ──
        if (url.indexOf('/oidc/') !== -1) {
            try {
                var reqBody = getRequestBody(req);
                send({ type: 'token_response', url: url, method: method, requestBody: reqBody, body: resp.peekBody(PEEK).string() });
            } catch (e) {}
            return resp;
        }

        // ── FULL TRAFFIC CAPTURE for VW domains (remote start discovery) ──
        if (isVwDomain(url)) {
            try {
                var reqBody = getRequestBody(req);
                var respBody = resp.peekBody(PEEK).string();
                var reqHeaders = getHeaders(hdrs);
                var respCode = resp.code();
                send({
                    type: 'full_traffic',
                    url: url,
                    method: method,
                    status: respCode,
                    requestHeaders: reqHeaders,
                    requestBody: reqBody,
                    responseBody: respBody
                });
            } catch (e) {
                send({ type: 'full_traffic', url: url, method: method, error: '' + e });
            }
        }

        // ── Also still publish known API responses for normal relay operation ──
        if (isApiUrl(url)) {
            try {
                send({ type: 'api_response', url: url, method: method, body: resp.peekBody(PEEK).string() });
            } catch (e) {}
        }

        return resp;
    };

    send({ type: 'status', msg: 'Hooks installed — FULL TRAFFIC capture + RST signing active' });
});

// ── RPC exports for remote start signing ──────────────────────────
rpc.exports = {
    // List all Android KeyStore aliases (for discovery)
    listKeystoreAliases: function () {
        var retval = null;
        Java.performNow(function () {
            try {
                var KeyStore = Java.use('java.security.KeyStore');
                var ks = KeyStore.getInstance('AndroidKeyStore');
                ks.load(null);
                var aliases = ks.aliases();
                var result = [];
                while (aliases.hasMoreElements()) {
                    result.push(aliases.nextElement().toString());
                }
                retval = JSON.stringify(result);
            } catch (e) {
                retval = JSON.stringify({ error: e.toString() });
            }
        });
        return retval || JSON.stringify({ error: 'Java.performNow returned without setting result' });
    },

    // Read SharedPreferences to find vehicle selection state
    readSharedPrefs: function (prefName) {
        var retval = null;
        Java.performNow(function () {
            try {
                var ActivityThread = Java.use('android.app.ActivityThread');
                var app = ActivityThread.currentApplication();
                var context = app.getApplicationContext();

                // List all SharedPreferences files if no name given
                if (!prefName || prefName === '') {
                    var prefsDir = context.getFilesDir().getParent() + '/shared_prefs';
                    var File = Java.use('java.io.File');
                    var dir = File.$new(prefsDir);
                    var files = dir.list();
                    var names = [];
                    if (files) {
                        for (var i = 0; i < files.length; i++) {
                            names.push(files[i].toString());
                        }
                    }
                    retval = JSON.stringify({ prefs_dir: prefsDir, files: names });
                    return;
                }

                // Read a specific SharedPreferences file
                var Context = Java.use('android.content.Context');
                var prefs = context.getSharedPreferences(prefName, 0);
                var allEntries = prefs.getAll();
                var map = {};
                var iterator = allEntries.entrySet().iterator();
                while (iterator.hasNext()) {
                    var entry = iterator.next();
                    var key = entry.getKey().toString();
                    var val = entry.getValue();
                    map[key] = val !== null ? val.toString() : null;
                }
                retval = JSON.stringify({ name: prefName, entries: map });
            } catch (e) {
                retval = JSON.stringify({ error: e.toString() });
            }
        });
        return retval || JSON.stringify({ error: 'Java.performNow returned without setting result' });
    },

    // Execute JS in React Native bridge (for navigation control)
    evalReactNative: function (jsCode) {
        var retval = null;
        Java.performNow(function () {
            try {
                // Find the CatalystInstance to evaluate JS
                var CatalystInstanceImpl = null;
                try { CatalystInstanceImpl = Java.use('com.facebook.react.bridge.CatalystInstanceImpl'); } catch(e) {}

                if (CatalystInstanceImpl) {
                    // Find running instances
                    Java.choose('com.facebook.react.bridge.CatalystInstanceImpl', {
                        onMatch: function (instance) {
                            try {
                                // loadScriptFromAssets doesn't work, but we can use NativeModules
                                retval = JSON.stringify({ found: true, msg: 'CatalystInstance found but direct JS eval not available. Use NativeModules approach.' });
                            } catch (e) {
                                retval = JSON.stringify({ error: 'instance eval failed: ' + e });
                            }
                        },
                        onComplete: function () {}
                    });
                }

                // Alternative: enumerate React Native modules
                if (!retval) {
                    var ReactContext = null;
                    try { ReactContext = Java.use('com.facebook.react.bridge.ReactContext'); } catch(e) {}
                    if (ReactContext) {
                        Java.choose('com.facebook.react.bridge.ReactContext', {
                            onMatch: function (ctx) {
                                try {
                                    var modules = ctx.getNativeModules();
                                    var names = [];
                                    var iterator = modules.entrySet().iterator();
                                    var count = 0;
                                    while (iterator.hasNext() && count < 50) {
                                        var entry = iterator.next();
                                        names.push(entry.getKey().toString());
                                        count++;
                                    }
                                    retval = JSON.stringify({ react_modules: names, total: modules.size() });
                                } catch (e) {
                                    retval = JSON.stringify({ error: 'module enum failed: ' + e });
                                }
                            },
                            onComplete: function () {}
                        });
                    }
                }

                if (!retval) retval = JSON.stringify({ error: 'No React Native bridge found' });
            } catch (e) {
                retval = JSON.stringify({ error: e.toString() });
            }
        });
        return retval || JSON.stringify({ error: 'Java.performNow returned without setting result' });
    },

    // Sign data with the VW pairing key from Android KeyStore
    // dataBase64: base64-encoded bytes to sign
    // alias: KeyStore alias (discovered via listKeystoreAliases)
    signWithKeystore: function (dataBase64, alias) {
        var retval = null;
        Java.performNow(function () {
            try {
                var KeyStore = Java.use('java.security.KeyStore');
                var Signature = Java.use('java.security.Signature');
                var Base64 = Java.use('android.util.Base64');

                var ks = KeyStore.getInstance('AndroidKeyStore');
                ks.load(null);

                if (!ks.containsAlias(alias)) {
                    retval = JSON.stringify({ error: 'alias_not_found', alias: alias });
                    return;
                }

                var entry = ks.getEntry(alias, null);
                // Detect key type and use appropriate algorithm
                var privateKey = Java.cast(entry, Java.use('java.security.KeyStore$PrivateKeyEntry')).getPrivateKey();
                var keyAlgo = privateKey.getAlgorithm();

                var sigAlgo;
                if (keyAlgo === 'EC') {
                    sigAlgo = 'SHA256withECDSA';
                } else if (keyAlgo === 'RSA') {
                    sigAlgo = 'SHA256withRSA';
                } else {
                    sigAlgo = 'SHA256with' + keyAlgo;
                }

                var sig = Signature.getInstance(sigAlgo);
                sig.initSign(privateKey);
                var dataBytes = Base64.decode(dataBase64, 0);
                sig.update(dataBytes);
                var sigBytes = sig.sign();
                var sigB64 = Base64.encodeToString(sigBytes, 2); // NO_WRAP
                retval = JSON.stringify({ signature: sigB64, algorithm: sigAlgo, keyType: keyAlgo });
            } catch (e) {
                retval = JSON.stringify({ error: e.toString() });
            }
        });
        return retval || JSON.stringify({ error: 'Java.performNow returned without setting result' });
    },
};
"""


class VWTokenRelay:
    def __init__(self, mqtt_host, mqtt_port=1883, mqtt_user=None, mqtt_pass=None,
                 vw_email=None, vw_password=None, vw_spin=None):
        self.mqtt_host = mqtt_host
        self.mqtt_port = mqtt_port
        self.mqtt_user = mqtt_user
        self.mqtt_pass = mqtt_pass

        # Auto-login credentials (for 30-day re-auth)
        self.vw_email = vw_email
        self.vw_password = vw_password
        self.vw_spin = vw_spin

        # PIF health tracking
        self._last_token_time = None  # set on every fresh token capture
        self._pif_reboot_cooldown = None  # prevent reboot loops

        # Token state — keyed by vehicle ID
        self.tokens = {}       # {vehicle_id: {"token": str, "expiry": datetime}}
        self.global_token = None  # most recent non-vehicle-scoped token
        self.global_expiry = None
        self.refresh_token = None
        self.id_token = None
        self.vehicle_ids = []
        self.user_id = None

        # Vehicle data cache — keyed by vehicle ID
        self.vehicle_data = {}  # {vehicle_id: {endpoint: response_dict}}

        # Frida
        self.session = None
        self.script = None
        self.device = None

        # MQTT
        self.mqttc = None

        self._lock = threading.RLock()
        self._running = True

    # ── MQTT ────────────────────────────────────────────────────────
    def _setup_mqtt(self):
        # paho-mqtt v2 requires callback_api_version
        try:
            self.mqttc = mqtt.Client(
                callback_api_version=mqtt.CallbackAPIVersion.VERSION1,
                client_id="vw-relay",
                protocol=mqtt.MQTTv311,
            )
        except (TypeError, AttributeError):
            # paho-mqtt v1 fallback
            self.mqttc = mqtt.Client(client_id="vw-relay", protocol=mqtt.MQTTv311)
        if self.mqtt_user:
            self.mqttc.username_pw_set(self.mqtt_user, self.mqtt_pass)
        self.mqttc.on_connect = self._on_mqtt_connect
        self.mqttc.on_message = self._on_mqtt_message
        self.mqttc.will_set(f"{MQTT_TOPIC_PREFIX}/status", "offline", retain=True)
        self.mqttc.connect(self.mqtt_host, self.mqtt_port)
        self.mqttc.loop_start()

    def _on_mqtt_connect(self, client, userdata, flags, rc):
        log.info("MQTT connected (rc=%d)", rc)
        client.subscribe(f"{MQTT_TOPIC_PREFIX}/cmd/#")
        client.publish(f"{MQTT_TOPIC_PREFIX}/status", "online", retain=True)

    def _on_mqtt_message(self, client, userdata, msg):
        topic = msg.topic
        payload = msg.payload.decode("utf-8", errors="replace")
        log.info("MQTT cmd: %s -> %s", topic, payload[:200])

        cmd = topic.replace(f"{MQTT_TOPIC_PREFIX}/cmd/", "")

        if cmd == "get_tokens":
            self._publish_tokens()
        elif cmd == "wake_app":
            threading.Thread(target=self._wake_app, daemon=True).start()
        elif cmd == "force_relaunch":
            threading.Thread(target=self._wake_app_full_restart, daemon=True).start()
        elif cmd == "screencap":
            threading.Thread(target=self._screencap, daemon=True).start()
        elif cmd == "vehicle_status":
            self._api_call("GET", payload)
        elif cmd == "lock":
            self._api_lock(payload, lock=True)
        elif cmd == "unlock":
            self._api_lock(payload, lock=False)
        elif cmd == "climate_start":
            self._api_climate(payload, start=True)
        elif cmd == "climate_stop":
            self._api_climate(payload, start=False)
        elif cmd == "remote_start":
            threading.Thread(target=self._api_remote_start, args=(payload,), daemon=True).start()
        elif cmd == "remote_start_stop":
            threading.Thread(target=self._api_remote_start_stop, args=(payload,), daemon=True).start()
        elif cmd == "dump_ui":
            threading.Thread(target=self._dump_ui, daemon=True).start()
        elif cmd == "dump_storage":
            threading.Thread(target=self._dump_rn_storage, daemon=True).start()
        elif cmd == "switch_vehicle":
            threading.Thread(target=self._switch_vehicle_rn, args=(payload,), daemon=True).start()
        elif cmd == "update_pif":
            threading.Thread(target=self._update_pif, daemon=True).start()
        elif cmd == "clear_data":
            threading.Thread(target=self._clear_app_data, daemon=True).start()
        elif cmd == "auto_login":
            threading.Thread(target=self._auto_login, daemon=True).start()
        else:
            log.warning("Unknown command: %s", cmd)

    def _publish_tokens(self):
        with self._lock:
            data = {
                "global_token": self.global_token[:80] + "..." if self.global_token else None,
                "global_expiry": self.global_expiry.isoformat() if self.global_expiry else None,
                "vehicle_tokens": {
                    vid: {
                        "token": t["token"][:80] + "...",
                        "expiry": t["expiry"].isoformat(),
                        "valid": datetime.now() < t["expiry"],
                    }
                    for vid, t in self.tokens.items()
                },
                "user_id": self.user_id,
                "vehicle_ids": self.vehicle_ids,
                "updated_at": datetime.now().isoformat(),
            }
        self.mqttc.publish(
            f"{MQTT_TOPIC_PREFIX}/tokens", json.dumps(data), retain=True
        )
        log.info("Published token summary to MQTT")

    # ── Direct API calls using captured tokens ──────────────────────
    def _get_valid_token(self, vehicle_id=None, vehicle_only=False):
        """Get a valid token, preferring vehicle-scoped if available.
        If vehicle_only=True, only return a vehicle-scoped token (required
        for vehicle-specific endpoints like pairing, SPIN, RST).
        VW backend validates tid strictly — cross-vehicle tokens get 403."""
        with self._lock:
            # 1. Exact vehicle match
            if vehicle_id and vehicle_id in self.tokens:
                t = self.tokens[vehicle_id]
                if datetime.now() < t["expiry"]:
                    return t["token"]
            # 2. Any vehicle-scoped token (only if no specific vehicle requested)
            if vehicle_only and not vehicle_id:
                for vid, t in self.tokens.items():
                    if datetime.now() < t["expiry"]:
                        log.info("TOKEN: Using %s-scoped token (any vehicle)", vid[:8])
                        return t["token"]
            # 3. Global token (no tid)
            if not vehicle_only:
                if self.global_token and self.global_expiry and datetime.now() < self.global_expiry:
                    return self.global_token
        return None

    def _api_request(self, method, url, body=None, vid=None, timeout=15):
        """Make an API request with auto-retry on auth or server failure.

        On 401/403: wakes the VW app for fresh tokens, waits, retries once.
        On 5xx: retries once after a short delay.
        Returns (response_body_str, None) on success, (None, error_dict) on failure.
        """
        max_retries = 1
        for attempt in range(max_retries + 1):
            token = self._get_valid_token(vid)
            if not token:
                if attempt < max_retries:
                    log.info("No valid token — waking app for refresh...")
                    self._wake_app()
                    time.sleep(30)
                    continue
                return None, {"error": "no_valid_token", "msg": "Token expired — no fresh token after retry"}

            headers = {**VW_API_HEADERS, "Authorization": f"Bearer {token}"}
            if self.user_id:
                headers["x-user-id"] = self.user_id

            req = Request(url, data=body, method=method, headers=headers)
            try:
                with urlopen(req, timeout=timeout) as resp:
                    return resp.read().decode(), None
            except HTTPError as e:
                err = e.read().decode("utf-8", errors="replace")
                if e.code in (401, 403) and attempt < max_retries:
                    log.warning("API %d on %s — refreshing token and retrying...", e.code, url[:60])
                    self._wake_app(target_vid=vid)
                    time.sleep(30)
                    continue
                if e.code >= 500 and attempt < max_retries:
                    log.warning("API %d on %s — server error, retrying in 10s...", e.code, url[:60])
                    time.sleep(10)
                    continue
                return None, {"error": f"http_{e.code}", "url": url, "body": err[:500], "code": e.code}
            except Exception as e:
                if attempt < max_retries:
                    log.warning("API exception on %s: %s — retrying...", url[:60], e)
                    time.sleep(5)
                    continue
                return None, {"error": "exception", "msg": str(e)}

        return None, {"error": "max_retries", "msg": "All retry attempts exhausted"}

    def _api_call(self, method, url_or_vid):
        """Make a direct API call using captured token."""
        vid = url_or_vid.strip()
        if not vid.startswith("http"):
            url = f"{BASE_URL}/rvs/v1/vehicle/{vid}"
        else:
            url = vid

        m = re.search(r"/vehicle/([0-9a-f-]{36})", url)
        vid = m.group(1) if m else None

        result, err = self._api_request(method, url, vid=vid)
        if result is not None:
            self.mqttc.publish(f"{MQTT_TOPIC_PREFIX}/response/vehicle_status", result)
            log.info("API call success: %s (%d bytes)", url[:80], len(result))
        else:
            log.error("API call failed: %s", err)
            self.mqttc.publish(f"{MQTT_TOPIC_PREFIX}/error", json.dumps(err))

    def _api_lock(self, vehicle_id, lock=True):
        """Send lock/unlock command with auto-retry."""
        vid = vehicle_id.strip()
        action = "lock" if lock else "unlock"
        url = f"{BASE_URL}/lockunlock/v1/vehicle/{vid}"
        body = json.dumps({"lock": lock}).encode()

        result, err = self._api_request("PUT", url, body=body, vid=vid)
        if result is not None:
            self.mqttc.publish(f"{MQTT_TOPIC_PREFIX}/response/{action}", result)
            log.info("%s success: %s", action.upper(), result[:200])
        else:
            log.error("%s failed: %s", action, err)

    def _api_climate(self, vehicle_id, start=True):
        """Send climate start/stop command with auto-retry."""
        vid = vehicle_id.strip()
        action = "start" if start else "stop"
        url = f"{BASE_URL}/ev/v1/vehicle/{vid}/pretripclimate/{action}"

        result, err = self._api_request("POST", url, body=b"", vid=vid)
        if result is not None:
            self.mqttc.publish(f"{MQTT_TOPIC_PREFIX}/response/climate", result)
            log.info("CLIMATE %s success: %s", action.upper(), result[:200])
        else:
            log.error("Climate %s failed: %s", action, err)
            self.mqttc.publish(f"{MQTT_TOPIC_PREFIX}/error",
                json.dumps({"error": f"climate_{err.get('code','?')}", "action": action}))

    # ── Remote Start (ICE vehicles) ──────────────────────────────────
    def _build_encrypted_payload(self, pairing_key_seed_hex, mobile_app_id):
        """Build the encryptedPayload for RemoteStartRequest.

        Crypto chain (from APK reverse engineering):
          1. Get current time as milliseconds, create 3 timestamp ints
          2. Convert each to 4-byte big-endian arrays
          3. Hex-decode pairingKeySeed to bytes
          4. XOR each timestamp array with key seed bytes (cycling)
          5. AES/ECB encrypt using key seed as 16-byte key
          6. XOR result with mobileAppId UTF-8 bytes (cycling)
          7. Base64-encode → encryptedPayload
        """
        key_seed_bytes = bytes.fromhex(pairing_key_seed_hex)

        now_ms = int(time.time() * 1000)
        timestamps = [now_ms & 0xFFFFFFFF, (now_ms >> 16) & 0xFFFFFFFF, (now_ms >> 32) & 0xFFFFFFFF]
        ts_bytes = b""
        for ts in timestamps:
            ts_bytes += struct.pack(">I", ts)

        # XOR with key seed (cycling)
        xored = bytes(d ^ key_seed_bytes[i % len(key_seed_bytes)] for i, d in enumerate(ts_bytes))

        # AES/ECB encrypt (pad key seed to 16 bytes)
        aes_key = key_seed_bytes
        if len(aes_key) < 16:
            aes_key = aes_key + b"\x00" * (16 - len(aes_key))
        elif len(aes_key) > 16:
            aes_key = aes_key[:16]

        plaintext = xored
        pad_len = 16 - (len(plaintext) % 16)
        if pad_len < 16:
            plaintext = plaintext + b"\x00" * pad_len

        cipher = Cipher(algorithms.AES(aes_key), modes.ECB())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(plaintext) + encryptor.finalize()

        # XOR with mobileAppId bytes (cycling)
        app_id_bytes = mobile_app_id.encode("utf-8")
        result = bytes(d ^ app_id_bytes[i % len(app_id_bytes)] for i, d in enumerate(encrypted))

        return base64.b64encode(result).decode("ascii")

    def _sign_with_keystore(self, data_b64):
        """Use Frida RPC to sign data with the phone's Android KeyStore key."""
        if not self.script:
            log.error("No Frida script loaded — cannot sign")
            return None

        try:
            # First discover the KeyStore alias if we haven't yet
            if not hasattr(self, '_keystore_alias') or self._keystore_alias is None:
                aliases_raw = self.script.exports_sync.list_keystore_aliases()
                if aliases_raw is None:
                    log.error("KeyStore: RPC returned None — Frida script may not be attached")
                    return None
                aliases_data = json.loads(aliases_raw)

                # Check if RPC returned an error
                if isinstance(aliases_data, dict) and "error" in aliases_data:
                    log.error("KeyStore alias listing failed: %s", aliases_data["error"])
                    return None

                aliases = aliases_data
                log.info("Android KeyStore aliases: %s", aliases)
                # Look for VW-related aliases
                vw_aliases = [a for a in aliases if any(k in a.lower() for k in ['vw', 'pairing', 'rst', 'remote', 'carnet'])]
                if vw_aliases:
                    self._keystore_alias = vw_aliases[0]
                    log.info("Using VW KeyStore alias: %s", self._keystore_alias)
                elif aliases:
                    # Try each alias — the VW key might have a generic name
                    for alias in aliases:
                        log.info("Trying KeyStore alias: %s", alias)
                        sign_raw = self.script.exports_sync.sign_with_keystore(data_b64, alias)
                        if sign_raw is None:
                            continue
                        result = json.loads(sign_raw)
                        if "signature" in result:
                            self._keystore_alias = alias
                            log.info("Found working KeyStore alias: %s (algo=%s, key=%s)",
                                     alias, result.get("algorithm", "?"), result.get("keyType", "?"))
                            return result["signature"]
                        else:
                            log.debug("KeyStore alias %s failed: %s", alias, result.get("error", "?"))
                    log.error("No working KeyStore alias found")
                    return None
                else:
                    log.error("No KeyStore aliases found (empty list)")
                    return None

            sign_raw = self.script.exports_sync.sign_with_keystore(data_b64, self._keystore_alias)
            if sign_raw is None:
                log.error("KeyStore signing returned None")
                self._keystore_alias = None
                return None
            result = json.loads(sign_raw)
            if "error" in result:
                log.error("KeyStore signing failed: %s", result)
                self._keystore_alias = None  # Reset for rediscovery
                return None
            log.info("KeyStore signed successfully (algo=%s, key=%s)",
                     result.get("algorithm", "?"), result.get("keyType", "?"))
            return result["signature"]
        except Exception as e:
            log.error("Frida RPC signing failed: %s", e)
            return None

    def _get_pairing_data(self, vehicle_id):
        """Get pairing data for a vehicle from the API.
        Uses _api_request for auto-retry on 401/403 (token refresh)."""
        url = f"{BASE_URL}/pair/v1/vehicle/{vehicle_id}"
        result, err = self._api_request("GET", url, vid=vehicle_id)
        if result is None:
            log.error("Get pairing failed: %s", err)
            return None

        try:
            body = json.loads(result)
            pairings = body.get("data", {}).get("pairings", [])
            # Find our phone's pairing (match by mobileAppId from headers)
            our_app_id = VW_API_HEADERS.get("x-app-uuid", "")
            for p in pairings:
                if p.get("mobileAppId", "").lower() == our_app_id.lower() and p.get("pairingStatus") == 4:
                    log.info("Found active pairing: pairingId=%s", p["pairingId"])
                    return p
            # Fallback: return any active pairing
            for p in pairings:
                if p.get("pairingStatus") == 4:
                    log.warning("Using fallback pairing (not our app): pairingId=%s", p["pairingId"])
                    return p
            log.error("No active pairing found for vehicle %s", vehicle_id)
            return None
        except (json.JSONDecodeError, KeyError) as e:
            log.error("Get pairing parse error: %s", e)
            return None

    def _api_remote_start(self, vehicle_id):
        """Execute remote start for an ICE vehicle.

        Flow (reverse-engineered from myVW APK):
          1. GET /pair/v1/vehicle/{vid} → get pairingId + pairingKeySeed
          2. GET /ss/v1/user/{uid}/challenge → get SPIN challenge
          3. Compute rstPinHash = SHA512(challenge + "." + spin).hex().upper()
          4. POST /ss/v1/user/{uid}/vehicle/{vid}/operation/climateControl/check
             body: {"spinHash": rstPinHash} → get roToken
          5. Build encryptedPayload (timestamps + XOR + AES/ECB + XOR + base64)
          6. Sign encryptedPayload via Frida RPC (Android KeyStore ECDSA)
          7. POST /rst/v1/vehicle/{vid}
             body: {pairingId, rstPinHash, encryptedPayload, roToken, dataToSign}
          8. Poll /history/v1/vehicle/{vid}/correlationId/{cid}/ro/ for result
        """
        vid = vehicle_id.strip()

        # Prevent concurrent RST commands
        if not hasattr(self, '_rst_lock'):
            self._rst_lock = threading.Lock()
        if not self._rst_lock.acquire(blocking=False):
            log.warning("RST: Another remote start is already in progress — ignoring")
            return
        try:
            self._api_remote_start_inner(vid)
        finally:
            self._rst_lock.release()

    def _api_remote_start_inner(self, vid):
        """Inner RST logic (runs under _rst_lock)."""
        log.info("═══ REMOTE START ═══ vehicle=%s", vid)

        if not self.vw_spin:
            self.mqttc.publish(f"{MQTT_TOPIC_PREFIX}/error",
                json.dumps({"error": "no_spin", "msg": "S-PIN not configured — required for remote start"}))
            return

        # Pre-check: vehicle-scoped endpoints (pairing, SPIN, RST) need tokens
        # with tid. Global tokens get 403. After app restart, only global tokens
        # exist until the app navigates to a vehicle dashboard.
        token = self._get_valid_token(vid, vehicle_only=True)
        if not token:
            # Phase 1: Light wake — navigate the running app (no force-stop)
            log.info("RST: No vehicle-scoped token — trying light navigation...")
            self._wake_app(target_vid=vid)
            for i in range(6):  # 30s polling
                time.sleep(5)
                token = self._get_valid_token(vid, vehicle_only=True)
                if token:
                    log.info("RST: Got vehicle-scoped token (light wake) after %ds", (i + 1) * 5)
                    break

        if not token:
            # Phase 2: Full restart — force-stop + relaunch + Frida reattach
            log.info("RST: Light wake failed — trying full app restart...")
            self._wake_app_full_restart(target_vid=vid)
            for i in range(8):  # 40s polling
                time.sleep(5)
                token = self._get_valid_token(vid, vehicle_only=True)
                if token:
                    log.info("RST: Got vehicle-scoped token (full restart) after %ds", (i + 1) * 5)
                    break
            if not token:
                log.error("RST: Still no vehicle-scoped token after light + full restart")
                self.mqttc.publish(f"{MQTT_TOPIC_PREFIX}/error",
                    json.dumps({"error": "no_valid_token", "msg": "No vehicle-scoped token after app navigation"}))
                return

        # Step 1: Get pairing data (uses _api_request with auto-retry on 403)
        log.info("RST Step 1: Getting pairing data...")
        pairing = self._get_pairing_data(vid)
        if not pairing:
            self.mqttc.publish(f"{MQTT_TOPIC_PREFIX}/error",
                json.dumps({"error": "no_pairing", "msg": "No active device pairing for this vehicle"}))
            return

        pairing_id = pairing["pairingId"]
        pairing_key_seed = pairing["pairingKeySeed"]
        mobile_app_id = pairing["mobileAppId"]

        # Step 2: Get SPIN challenge
        log.info("RST Step 2: Getting SPIN challenge...")
        challenge_url = f"{BASE_URL}/ss/v1/user/{self.user_id}/challenge"
        result, err = self._api_request("GET", challenge_url, vid=vid)
        if result is None:
            log.error("SPIN challenge failed: %s", err)
            self.mqttc.publish(f"{MQTT_TOPIC_PREFIX}/error",
                json.dumps({"error": "spin_challenge_failed", **err}))
            return

        challenge_data = json.loads(result)
        challenge = challenge_data["data"]["challenge"]
        remaining = challenge_data["data"]["remainingTries"]
        log.info("RST: challenge=%s, remainingTries=%d", challenge, remaining)

        if remaining < 3:
            log.warning("RST: Only %d SPIN tries remaining — aborting", remaining)
            self.mqttc.publish(f"{MQTT_TOPIC_PREFIX}/error",
                json.dumps({"error": "spin_low_tries", "remaining": remaining}))
            return

        # Step 3: Compute rstPinHash
        rst_pin_hash = hashlib.sha512(f"{challenge}.{self.vw_spin}".encode()).hexdigest().upper()
        log.info("RST Step 3: Computed rstPinHash (%d chars)", len(rst_pin_hash))

        # Step 4: SPIN check → get roToken
        log.info("RST Step 4: SPIN check for roToken...")
        check_url = f"{BASE_URL}/ss/v1/user/{self.user_id}/vehicle/{vid}/operation/climateControl/check"
        check_body = json.dumps({"spinHash": rst_pin_hash}).encode()
        result, err = self._api_request("POST", check_url, body=check_body, vid=vid)
        if result is None:
            log.error("SPIN check failed: %s", err)
            self.mqttc.publish(f"{MQTT_TOPIC_PREFIX}/error",
                json.dumps({"error": "spin_check_failed", **err}))
            return

        check_data = json.loads(result)
        ro_token = check_data["data"]["roToken"]
        captcha_idx = check_data["data"].get("captchaIndex", "")
        captcha_val = check_data["data"].get("captchaValue", "")
        log.info("RST: Got roToken (%d chars), captcha=%s/%s", len(ro_token), captcha_idx, captcha_val)

        # Step 5: Build encrypted payload
        log.info("RST Step 5: Building encrypted payload...")
        encrypted_payload = self._build_encrypted_payload(pairing_key_seed, mobile_app_id)
        log.info("RST: encryptedPayload=%s", encrypted_payload)

        # Step 6: Sign with KeyStore via Frida
        log.info("RST Step 6: Signing with Android KeyStore...")
        data_to_sign = self._sign_with_keystore(encrypted_payload)
        if not data_to_sign:
            log.warning("RST: KeyStore signing failed — trying without signature")
            data_to_sign = ""

        # Step 7: POST to /rst/v1/
        log.info("RST Step 7: Sending remote start command...")
        rst_url = f"{BASE_URL}/rst/v1/vehicle/{vid}"
        rst_body = json.dumps({
            "pairingId": pairing_id,
            "rstPinHash": rst_pin_hash,
            "encryptedPayload": encrypted_payload,
            "roToken": ro_token,
            "dataToSign": data_to_sign,
        }).encode()
        log.info("RST: POST body size=%d bytes", len(rst_body))

        result, err = self._api_request("POST", rst_url, body=rst_body, vid=vid, timeout=30)
        if result is None:
            log.error("Remote start POST failed: %s", err)
            self.mqttc.publish(f"{MQTT_TOPIC_PREFIX}/error",
                json.dumps({"error": "rst_post_failed", **err}))
            return

        rst_data = json.loads(result)
        log.info("RST: POST response: %s", json.dumps(rst_data)[:500])

        # Extract correlationId for polling
        correlation_id = rst_data.get("data", {}).get("correlationId")
        if not correlation_id:
            self.mqttc.publish(f"{MQTT_TOPIC_PREFIX}/{vid}/remote_start",
                json.dumps(rst_data), retain=False)
            log.info("RST: No correlationId in response — published raw result")
            return

        # Step 8: Poll for result (uses _api_request for auto-retry)
        log.info("RST Step 8: Polling for result (correlationId=%s)...", correlation_id)
        self.mqttc.publish(f"{MQTT_TOPIC_PREFIX}/{vid}/remote_start",
            json.dumps({"status": "pending", "correlationId": correlation_id}), retain=False)

        poll_url = f"{BASE_URL}/history/v1/vehicle/{vid}/correlationId/{correlation_id}/ro/"
        for attempt in range(12):  # Poll up to 2 minutes
            time.sleep(10)
            poll_result, poll_err = self._api_request("GET", poll_url, vid=vid)
            if poll_result is not None:
                poll_data = json.loads(poll_result)
                status_str = poll_data.get("data", {}).get("responseStatusString", "")
                outcome_str = poll_data.get("data", {}).get("responseOutcomeString", "")
                telem_code = poll_data.get("data", {}).get("telematicsResponseCode", "")
                telem_value = poll_data.get("data", {}).get("telematicsResponseValue", "")

                log.info("RST poll %d: status=%s outcome=%s telem=%s/%s",
                         attempt + 1, status_str, outcome_str, telem_code, telem_value)

                self.mqttc.publish(f"{MQTT_TOPIC_PREFIX}/{vid}/remote_start",
                    json.dumps({
                        "status": status_str,
                        "outcome": outcome_str,
                        "telematicsCode": telem_code,
                        "telematicsValue": telem_value,
                        "correlationId": correlation_id,
                        "attempt": attempt + 1,
                    }), retain=False)

                if status_str == "ACKNOWLEDGED":
                    if outcome_str in ("ACCEPTED", "REJECTED"):
                        if outcome_str == "ACCEPTED":
                            log.info("═══ REMOTE START SUCCESS ═══")
                        else:
                            log.warning("═══ REMOTE START REJECTED: %s (%s) ═══", telem_value, telem_code)
                        return
            else:
                code = poll_err.get("code", 0) if isinstance(poll_err, dict) else 0
                if code == 404:
                    log.debug("RST poll %d: not ready yet (404)", attempt + 1)
                else:
                    log.error("RST poll %d failed: %s", attempt + 1, poll_err)

        log.warning("RST: Polling timed out after %d attempts", 12)
        self.mqttc.publish(f"{MQTT_TOPIC_PREFIX}/{vid}/remote_start",
            json.dumps({"status": "timeout", "correlationId": correlation_id}), retain=False)

    def _api_remote_start_stop(self, vehicle_id):
        """Stop a running remote start with auto-retry."""
        vid = vehicle_id.strip()
        url = f"{BASE_URL}/rst/v1/vehicle/{vid}"

        result, err = self._api_request("DELETE", url, vid=vid)
        if result is not None:
            log.info("RST STOP success: %s", result[:200])
            self.mqttc.publish(f"{MQTT_TOPIC_PREFIX}/{vid}/remote_start",
                json.dumps({"status": "stopped"}), retain=False)
        else:
            log.error("RST stop failed: %s", err)

    # ── Wake the VW app to trigger token refresh ────────────────────
    def _adb_check(self):
        """Verify ADB can reach the phone. Returns True if device is online."""
        try:
            result = subprocess.run(
                ["adb", "devices"], capture_output=True, text=True, timeout=5,
            )
            lines = [l for l in result.stdout.strip().splitlines()
                     if l and not l.startswith("List") and "device" in l]
            if lines:
                log.debug("ADB: device(s) online: %s", lines)
                return True
            # No device — try reconnecting USB
            log.warning("ADB: no device found — running adb reconnect")
            subprocess.run(["adb", "kill-server"], capture_output=True, timeout=5)
            time.sleep(1)
            subprocess.run(["adb", "start-server"], capture_output=True, timeout=5)
            time.sleep(2)
            result2 = subprocess.run(
                ["adb", "devices"], capture_output=True, text=True, timeout=5,
            )
            lines2 = [l for l in result2.stdout.strip().splitlines()
                      if l and not l.startswith("List") and "device" in l]
            if lines2:
                log.info("ADB: device reconnected: %s", lines2)
                return True
            log.error("ADB: still no device after reconnect")
            return False
        except Exception as e:
            log.error("ADB: device check failed: %s", e)
            return False

    def _adb_tap(self, x, y, label=""):
        """Send an ADB tap at specific coordinates.
        'input tap' hangs as shell user on Moto G Pure but works via su."""
        log.info("NAV: Tapping %s at (%d, %d)", label, x, y)

        # Method 1: input tap via su (root) — this bypasses the permission
        # issue that causes 'input tap' to hang as shell user
        try:
            result = subprocess.run(
                ["adb", "shell", "su", "-c",
                 f"input tap {x} {y}"],
                capture_output=True, timeout=10,
            )
            if result.returncode == 0:
                log.info("NAV: su input tap succeeded at (%d, %d)", x, y)
                return True
            log.warning("NAV: su input tap failed (rc=%d)", result.returncode)
        except subprocess.TimeoutExpired:
            log.warning("NAV: su input tap timed out — trying sendevent")
        except Exception as e:
            log.warning("NAV: su input tap error: %s", e)

        # Method 2: sendevent (raw touch events)
        try:
            # Find touchscreen device
            result = subprocess.run(
                ["adb", "shell", "cat", "/proc/bus/input/devices"],
                capture_output=True, text=True, timeout=5,
            )
            ts_dev = None
            dev_lines = result.stdout.split('\n')
            for i, line in enumerate(dev_lines):
                if 'touch' in line.lower():
                    for j in range(i, min(i + 10, len(dev_lines))):
                        if 'Handlers=' in dev_lines[j] and 'event' in dev_lines[j]:
                            import re as _re
                            m = _re.search(r'(event\d+)', dev_lines[j])
                            if m:
                                ts_dev = f"/dev/input/{m.group(1)}"
                                break
                    if ts_dev:
                        break

            if ts_dev:
                cmds = (
                    f"sendevent {ts_dev} 3 57 0;"
                    f"sendevent {ts_dev} 3 53 {x};"
                    f"sendevent {ts_dev} 3 54 {y};"
                    f"sendevent {ts_dev} 1 330 1;"
                    f"sendevent {ts_dev} 0 0 0;"
                    f"sleep 0.05;"
                    f"sendevent {ts_dev} 3 57 -1;"
                    f"sendevent {ts_dev} 1 330 0;"
                    f"sendevent {ts_dev} 0 0 0"
                )
                r = subprocess.run(
                    ["adb", "shell", f"su -c '{cmds}'"],
                    capture_output=True, timeout=10,
                )
                if r.returncode == 0:
                    log.info("NAV: sendevent tap succeeded at (%d, %d)", x, y)
                    return True
                log.warning("NAV: sendevent failed (rc=%d)", r.returncode)
        except Exception as e:
            log.warning("NAV: sendevent failed: %s", e)

        # Method 3: input tap as shell user (last resort, may hang)
        try:
            result = subprocess.run(
                ["adb", "shell", "input", "tap", str(x), str(y)],
                capture_output=True, timeout=8,
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            log.error("NAV: All tap methods failed at (%d, %d)", x, y)
            return False

    def _adb_swipe(self, x1, y1, x2, y2, duration_ms=300, label=""):
        """Send an ADB swipe. Uses su to avoid hanging on Moto G Pure."""
        log.info("NAV: Swiping %s (%d,%d)->(%d,%d)", label, x1, y1, x2, y2)
        try:
            result = subprocess.run(
                ["adb", "shell", "su", "-c",
                 f"input swipe {x1} {y1} {x2} {y2} {duration_ms}"],
                capture_output=True, timeout=10,
            )
            return result.returncode == 0
        except Exception as e:
            log.warning("NAV: swipe failed: %s", e)
            return False

    def _navigate_to_vehicle(self, target_vid=None):
        """Navigate the VW app to trigger vehicle-scoped API calls.
        If target_vid is specified, tries multiple strategies to reach it.
        React Native views are invisible to uiautomator, so we use
        blind taps/swipes at known positions on Moto G Pure (720x1600).

        Key insight: The VW myVW app uses a bottom navigation bar. The
        home tab shows ONE vehicle at a time. Vehicle switching is via
        a picker/dropdown or a separate "garage" tab — NOT a swipeable
        carousel on the home screen."""
        if not self._adb_check():
            log.error("NAV: Cannot navigate — ADB not connected")
            return False

        def _check_target():
            if not target_vid:
                return False
            return self._get_valid_token(target_vid, vehicle_only=True) is not None

        def _ensure_app_fg():
            """Make sure VW app is in foreground."""
            fg = self._get_foreground_activity()
            if VW_PACKAGE not in (fg or ''):
                log.info("NAV: App not in FG (%s) — relaunching", fg[:40] if fg else 'none')
                try:
                    subprocess.run(
                        ["adb", "shell", "am", "start", "-n",
                         f"{VW_PACKAGE}/com.vw.myVW.activities.RoutingActivity"],
                        capture_output=True, timeout=10,
                    )
                    time.sleep(6)
                except Exception:
                    pass

        try:
            _ensure_app_fg()

            # ── Strategy 0: Tap the default vehicle card area ──
            log.info("NAV: S0 — tap default card area (360,600)")
            self._adb_tap(360, 600, label="S0-default")
            time.sleep(4)

            if not target_vid:
                return True
            if _check_target():
                log.info("NAV: Got target token from default tap")
                return True

            # ── Strategy 1: Vehicle picker/dropdown at top of screen ──
            # Many car apps have the vehicle name at the top that opens a picker.
            log.info("NAV: S1 — tap vehicle picker areas at top of screen")
            _ensure_app_fg()
            # Tap top center (vehicle name area)
            self._adb_tap(360, 150, label="S1-top-center")
            time.sleep(3)
            # If a dropdown appeared, tap the second item
            self._adb_tap(360, 300, label="S1-dropdown-item2")
            time.sleep(5)
            if _check_target():
                log.info("NAV: S1 — got target from top picker")
                return True
            # Try tapping a third position in case the dropdown has headers
            self._adb_tap(360, 400, label="S1-dropdown-item3")
            time.sleep(5)
            if _check_target():
                log.info("NAV: S1 — got target from picker item 3")
                return True

            # ── Strategy 2: Bottom navigation tabs ──
            # VW app has a bottom nav bar. Try each tab to find "Garage".
            # On 720x1600, bottom nav is around Y=1540-1560.
            # Common 4-tab positions: x=90, 270, 450, 630
            # Common 5-tab positions: x=72, 216, 360, 504, 648
            log.info("NAV: S2 — tap bottom navigation tabs")
            _ensure_app_fg()
            # Try each bottom tab position
            for tab_x in [90, 270, 450, 630]:
                self._adb_tap(tab_x, 1550, label=f"S2-btab-{tab_x}")
                time.sleep(3)
                # After switching tab, look for vehicle list items
                # Tap various Y positions to find Atlas card
                for card_y in [400, 600, 800, 1000]:
                    self._adb_tap(360, card_y, label=f"S2-card-y{card_y}")
                    time.sleep(4)
                    if _check_target():
                        log.info("NAV: S2 — got target from tab x=%d, card y=%d", tab_x, card_y)
                        return True

            # ── Strategy 3: Hamburger menu (top-left) ──
            log.info("NAV: S3 — try hamburger menu (top-left)")
            _ensure_app_fg()
            self._adb_tap(50, 80, label="S3-hamburger")
            time.sleep(3)
            # Look for vehicle entries in side menu
            for menu_y in [300, 400, 500, 600, 700]:
                self._adb_tap(300, menu_y, label=f"S3-menu-y{menu_y}")
                time.sleep(3)
                if _check_target():
                    log.info("NAV: S3 — got target from menu y=%d", menu_y)
                    return True
                # If we entered a sub-screen, check for vehicle items
                for sub_y in [400, 600, 800]:
                    self._adb_tap(360, sub_y, label=f"S3-sub-y{sub_y}")
                    time.sleep(3)
                    if _check_target():
                        log.info("NAV: S3 — got target from sub-menu y=%d", sub_y)
                        return True

            # ── Strategy 4: Top-right menu/kebab ──
            log.info("NAV: S4 — try top-right menu")
            _ensure_app_fg()
            self._adb_tap(670, 80, label="S4-kebab")
            time.sleep(3)
            for menu_y in [200, 300, 400, 500]:
                self._adb_tap(500, menu_y, label=f"S4-menu-y{menu_y}")
                time.sleep(3)
                if _check_target():
                    log.info("NAV: S4 — got target from top-right menu y=%d", menu_y)
                    return True

            # ── Strategy 5: Swipe left on detail screen ──
            log.info("NAV: S5 — swipe left on main screen")
            _ensure_app_fg()
            self._adb_tap(360, 600, label="S5-enter-detail")
            time.sleep(3)
            for i in range(3):
                self._adb_swipe(600, 800, 100, 800, 400, f"S5-swipe-left-{i+1}")
                time.sleep(5)
                if _check_target():
                    log.info("NAV: S5 — got target after swipe %d", i + 1)
                    return True

            log.warning("NAV: All strategies exhausted — no target vehicle token")
            # Take screenshot for debugging (goes to /config/www/vw_screen.png)
            _ensure_app_fg()
            time.sleep(2)
            self._screencap()
            return False

        except Exception as e:
            log.error("NAV: Navigation failed: %s", e)
            return False

    def _wake_screen(self):
        """Wake the screen and dismiss lock screen. Best effort."""
        try:
            subprocess.run(
                ["adb", "shell", "input", "keyevent", "KEYCODE_WAKEUP"],
                capture_output=True, timeout=10,
            )
            time.sleep(1)
        except Exception as e:
            log.warning("WAKE: screen wake failed (non-critical): %s", e)
        try:
            subprocess.run(
                ["adb", "shell", "su", "-c", "input swipe 540 1800 540 800 300"],
                capture_output=True, timeout=10,
            )
            time.sleep(1)
        except Exception as e:
            log.warning("WAKE: lock screen swipe failed (non-critical): %s", e)
        try:
            subprocess.run(
                ["adb", "shell", "wm", "dismiss-keyguard"],
                capture_output=True, timeout=5,
            )
        except Exception:
            pass

    def _get_foreground_activity(self):
        """Get the current foreground activity name."""
        try:
            r = subprocess.run(
                ["adb", "shell", "dumpsys", "activity", "activities"],
                capture_output=True, text=True, timeout=10,
            )
            for line in r.stdout.split('\n'):
                if 'mResumedActivity' in line or 'topResumedActivity' in line:
                    return line.strip()
            return "unknown"
        except Exception:
            return "error"

    def _wake_app(self, target_vid=None):
        """Get VW app to a vehicle dashboard for vehicle-scoped tokens.
        Strategy:
          1. Try navigating the already-running app first (no force-stop).
             Force-stopping + relaunching causes white screen on Moto G Pure.
          2. Only force-stop if the app isn't in the foreground."""
        if not self._adb_check():
            log.error("WAKE: Cannot wake app — ADB not connected")
            return

        self._wake_screen()

        # Check if VW app is already running in foreground
        fg = self._get_foreground_activity()
        log.info("WAKE: Foreground activity: %s", fg)

        vw_in_fg = VW_PACKAGE in fg if fg else False

        if not vw_in_fg:
            log.info("WAKE: VW app not in foreground — launching...")
            try:
                subprocess.run(
                    ["adb", "shell", "am", "start", "-n",
                     f"{VW_PACKAGE}/com.vw.myVW.activities.RoutingActivity"],
                    capture_output=True, timeout=10,
                )
                time.sleep(10)
            except Exception as e:
                log.error("WAKE: Failed to launch VW app: %s", e)
                return
        else:
            log.info("WAKE: VW app already in foreground")

        log.info("WAKE: Attempting navigation on running app...")
        time.sleep(3)
        self._navigate_to_vehicle(target_vid=target_vid)

    def _wake_app_full_restart(self, target_vid=None):
        """Full force-stop + relaunch cycle. Called if light wake didn't
        produce vehicle-scoped tokens. Gives the app more time to render
        before Frida re-attach."""
        if not self._adb_check():
            log.error("WAKE: Cannot wake app — ADB not connected")
            return

        self._wake_screen()

        log.info("WAKE: Full restart — force-stopping VW app...")
        try:
            subprocess.run(
                ["adb", "shell", "am", "force-stop", VW_PACKAGE],
                capture_output=True, timeout=10,
            )
            time.sleep(3)
            log.info("WAKE: Relaunching VW app...")
            subprocess.run(
                ["adb", "shell", "am", "start", "-n",
                 f"{VW_PACKAGE}/com.vw.myVW.activities.RoutingActivity"],
                capture_output=True, timeout=10,
            )
        except Exception as e:
            log.error("WAKE: Failed to restart VW app: %s", e)
            return

        log.info("WAKE: Waiting 12s for React Native to init before Frida attach...")
        time.sleep(12)
        try:
            self._attach_frida()
        except Exception as e:
            log.error("WAKE: Failed to reattach Frida: %s", e)

        log.info("WAKE: Waiting 20s for vehicle cards to render...")
        time.sleep(20)
        self._navigate_to_vehicle(target_vid=target_vid)

    def _screencap(self):
        """Take a screenshot of the phone and save to /share/ for debugging."""
        try:
            log.info("SCREENCAP: Taking screenshot...")

            # Method 1: Use su for screencap (more reliable on rooted phones)
            r1 = subprocess.run(
                ["adb", "shell", "su", "-c", "screencap -p /data/local/tmp/vw_screen.png"],
                capture_output=True, text=True, timeout=30,
            )
            log.info("SCREENCAP: capture rc=%d stdout=%s stderr=%s",
                     r1.returncode, r1.stdout.strip()[:100], r1.stderr.strip()[:100])

            # Pull with verbose output
            r2 = subprocess.run(
                ["adb", "pull", "/data/local/tmp/vw_screen.png", "/share/vw_screen.png"],
                capture_output=True, text=True, timeout=15,
            )
            log.info("SCREENCAP: pull rc=%d stdout=%s stderr=%s",
                     r2.returncode, r2.stdout.strip()[:100], r2.stderr.strip()[:100])

            # Check if file exists and its size
            import os
            if os.path.exists("/share/vw_screen.png"):
                sz = os.path.getsize("/share/vw_screen.png")
                log.info("SCREENCAP: File exists, size=%d bytes", sz)
            else:
                log.error("SCREENCAP: File NOT created at /share/vw_screen.png")
                # Fallback: try piping screencap directly
                log.info("SCREENCAP: Trying pipe method...")
                r3 = subprocess.run(
                    ["adb", "exec-out", "su", "-c", "screencap -p"],
                    capture_output=True, timeout=30,
                )
                if r3.stdout and len(r3.stdout) > 1000:
                    with open("/share/vw_screen.png", "wb") as f:
                        f.write(r3.stdout)
                    log.info("SCREENCAP: Pipe method saved %d bytes", len(r3.stdout))
                else:
                    log.error("SCREENCAP: Pipe method failed (got %d bytes)", len(r3.stdout) if r3.stdout else 0)

            # Log the current activity for context
            fg = self._get_foreground_activity()
            log.info("SCREENCAP: Current foreground: %s", fg)

            if os.path.exists("/share/vw_screen.png"):
                sz = os.path.getsize("/share/vw_screen.png")
                # Base64 encode + HTML viewer for ingress proxy
                import base64
                try:
                    with open("/share/vw_screen.png", "rb") as f:
                        b64 = base64.b64encode(f.read()).decode()
                    with open("/share/vw_screen_b64.txt", "w") as f:
                        f.write(b64)
                    # Write HTML viewer with embedded image
                    html = (
                        '<!DOCTYPE html><html><head><meta charset="utf-8">'
                        '<title>Phone Screen</title>'
                        '<style>body{margin:0;background:#111;display:flex;'
                        'justify-content:center;align-items:flex-start;min-height:100vh}'
                        'img{max-height:100vh;width:auto}</style></head>'
                        f'<body><img src="data:image/png;base64,{b64}"/>'
                        '</body></html>'
                    )
                    with open("/share/vw_screen.html", "w") as f:
                        f.write(html)
                    log.info("SCREENCAP: Base64+HTML written (%d chars)", len(b64))
                except Exception as be:
                    log.error("SCREENCAP: Base64 encode failed: %s", be)
                self.mqttc.publish(
                    f"{MQTT_TOPIC_PREFIX}/screencap",
                    json.dumps({"status": "saved", "path": "/share/vw_screen.png",
                                "size": sz, "b64_path": "/share/vw_screen_b64.txt"}),
                )
            else:
                self.mqttc.publish(
                    f"{MQTT_TOPIC_PREFIX}/screencap",
                    json.dumps({"status": "error", "msg": "File not created"}),
                )
        except Exception as e:
            log.error("SCREENCAP: Failed: %s", e)
            self.mqttc.publish(
                f"{MQTT_TOPIC_PREFIX}/screencap",
                json.dumps({"status": "error", "msg": str(e)}),
            )

    def _dump_ui(self):
        """Dump phone UI info via multiple methods for debugging.
        Combines dumpsys, Frida SharedPrefs, and RN module enumeration."""
        try:
            log.info("DUMP_UI: Starting comprehensive UI dump...")

            # 1. dumpsys activity top — shows current activity view hierarchy
            try:
                r = subprocess.run(
                    ["adb", "shell", "dumpsys", "activity", "top"],
                    capture_output=True, text=True, timeout=15,
                )
                # Extract just the top activity section
                lines = r.stdout.split('\n')
                relevant = []
                capture = False
                for line in lines:
                    if 'ACTIVITY' in line and 'com.vw' in line:
                        capture = True
                    if capture:
                        relevant.append(line)
                    if capture and len(relevant) > 60:
                        break
                for line in relevant[:40]:
                    log.info("DUMP_UI activity: %s", line.rstrip()[:200])
            except Exception as e:
                log.warning("DUMP_UI: dumpsys activity top failed: %s", e)

            # 2. dumpsys window — shows window dimensions and layout
            try:
                r = subprocess.run(
                    ["adb", "shell", "dumpsys", "window", "windows"],
                    capture_output=True, text=True, timeout=15,
                )
                for line in r.stdout.split('\n'):
                    if 'com.vw' in line or 'mFrame' in line or 'mContaining' in line:
                        log.info("DUMP_UI window: %s", line.strip()[:200])
            except Exception as e:
                log.warning("DUMP_UI: dumpsys window failed: %s", e)

            # 3. Frida SharedPreferences — find vehicle selection state
            if self.script:
                try:
                    # List all prefs files
                    prefs_list = self.script.exports_sync.read_shared_prefs("")
                    prefs_data = json.loads(prefs_list)
                    log.info("DUMP_UI prefs files: %s", json.dumps(prefs_data.get("files", []))[:500])

                    # Read each prefs file looking for vehicle-related keys
                    for pf in prefs_data.get("files", []):
                        pname = pf.replace(".xml", "")
                        try:
                            pdata = self.script.exports_sync.read_shared_prefs(pname)
                            pd = json.loads(pdata)
                            entries = pd.get("entries", {})
                            # Look for vehicle-related keys
                            for k, v in entries.items():
                                kl = k.lower()
                                if any(term in kl for term in ["vehicle", "car", "vin", "garage",
                                        "selected", "default", "current", "active", "atlas", "buzz"]):
                                    log.info("DUMP_UI pref [%s] %s = %s", pname, k, str(v)[:200])
                        except Exception as e2:
                            log.debug("DUMP_UI: prefs read %s failed: %s", pname, e2)
                except Exception as e:
                    log.warning("DUMP_UI: SharedPrefs read failed: %s", e)

                # 4. React Native module enumeration
                try:
                    rn_info = self.script.exports_sync.eval_react_native("")
                    rn_data = json.loads(rn_info)
                    log.info("DUMP_UI RN modules: %s", json.dumps(rn_data)[:500])
                except Exception as e:
                    log.warning("DUMP_UI: RN module enum failed: %s", e)
            else:
                log.warning("DUMP_UI: No Frida script — skipping SharedPrefs and RN dump")

            # 5. Foreground activity
            fg = self._get_foreground_activity()
            log.info("DUMP_UI: Foreground: %s", fg)

            self.mqttc.publish(
                f"{MQTT_TOPIC_PREFIX}/ui_dump",
                json.dumps({"status": "ok", "msg": "See addon logs for full dump"}),
            )

        except Exception as e:
            log.error("DUMP_UI: Failed: %s", e)
            self.mqttc.publish(
                f"{MQTT_TOPIC_PREFIX}/ui_dump",
                json.dumps({"status": "error", "msg": str(e)}),
            )

    # ── Helper: run a command via adb shell + su ──
    def _adb_su(self, cmd, timeout=15):
        """Run a command as root via adb. Properly quotes for su -c."""
        # Pass entire su command as one string so adb shell's sh keeps it intact
        r = subprocess.run(
            ["adb", "shell", f"su -c '{cmd}'"],
            capture_output=True, text=True, timeout=timeout,
        )
        return r

    def _dump_rn_storage(self):
        """Dump React Native AsyncStorage (SQLite DB) for vehicle data discovery.
        Phone has no sqlite3, so we pull DB files and query locally with Python."""
        import sqlite3 as pysqlite
        try:
            log.info("RN_STORAGE: Reading AsyncStorage database...")
            remote_db_dir = f"/data/data/{VW_PACKAGE}/databases"
            local_tmp = "/tmp/vw_db_dump"
            os.makedirs(local_tmp, exist_ok=True)

            # 1. List all databases on phone
            r = self._adb_su(f"ls -la {remote_db_dir}/")
            log.info("RN_STORAGE: databases dir:\n%s", r.stdout.strip()[:1000])

            # 2. Pull RKStorage to local and query with Python sqlite3
            # Copy from app-private dir to /data/local/tmp first (adb pull needs accessible path)
            self._adb_su(f"cp {remote_db_dir}/RKStorage /data/local/tmp/RKStorage")
            self._adb_su(f"chmod 644 /data/local/tmp/RKStorage")
            r = subprocess.run(
                ["adb", "pull", "/data/local/tmp/RKStorage", f"{local_tmp}/RKStorage"],
                capture_output=True, text=True, timeout=15,
            )
            log.info("RN_STORAGE: pull RKStorage: %s %s", r.stdout.strip(), r.stderr.strip())

            rk_path = f"{local_tmp}/RKStorage"
            if os.path.exists(rk_path) and os.path.getsize(rk_path) > 0:
                conn = pysqlite.connect(rk_path)
                cur = conn.cursor()

                # List tables
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in cur.fetchall()]
                log.info("RN_STORAGE: RKStorage tables: %s", tables)

                for table in tables:
                    cur.execute(f"SELECT * FROM [{table}] LIMIT 100")
                    cols = [d[0] for d in cur.description]
                    rows = cur.fetchall()
                    log.info("RN_STORAGE: [%s] cols=%s, %d rows", table, cols, len(rows))
                    for row in rows:
                        # Truncate values for logging
                        row_str = " | ".join(str(v)[:200] for v in row)
                        log.info("RN_STORAGE: [%s] %s", table, row_str[:400])

                conn.close()
            else:
                log.warning("RN_STORAGE: RKStorage pull failed or empty")

            # 3. Also pull any other .db files
            db_files = r.stdout.strip() if r else ""
            for line in (self._adb_su(f"ls {remote_db_dir}/").stdout or "").split():
                fname = line.strip()
                if fname and fname != "RKStorage" and not fname.endswith("-journal") and not fname.endswith("-wal"):
                    self._adb_su(f"cp {remote_db_dir}/{fname} /data/local/tmp/{fname}")
                    self._adb_su(f"chmod 644 /data/local/tmp/{fname}")
                    r2 = subprocess.run(
                        ["adb", "pull", f"/data/local/tmp/{fname}", f"{local_tmp}/{fname}"],
                        capture_output=True, text=True, timeout=15,
                    )
                    local_path = f"{local_tmp}/{fname}"
                    if os.path.exists(local_path) and os.path.getsize(local_path) > 100:
                        try:
                            conn = pysqlite.connect(local_path)
                            cur = conn.cursor()
                            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                            db_tables = [r[0] for r in cur.fetchall()]
                            log.info("RN_STORAGE: [%s] tables: %s", fname, db_tables)
                            # Search for vehicle-related data
                            for t in db_tables:
                                try:
                                    cur.execute(f"SELECT * FROM [{t}] LIMIT 5")
                                    sample = cur.fetchall()
                                    if sample:
                                        cols = [d[0] for d in cur.description]
                                        log.info("RN_STORAGE: [%s.%s] cols=%s sample=%s",
                                                 fname, t, cols, str(sample[0])[:200])
                                except Exception:
                                    pass
                            conn.close()
                        except Exception as e:
                            log.debug("RN_STORAGE: %s not a valid DB: %s", fname, e)

            # 4. Grep SharedPreferences XML files for vehicle IDs
            r = self._adb_su(f"ls /data/data/{VW_PACKAGE}/shared_prefs/")
            prefs_files = r.stdout.strip().split() if r.stdout.strip() else []
            log.info("RN_STORAGE: SharedPrefs files: %s", prefs_files[:20])

            for pf in prefs_files[:15]:
                pf = pf.strip()
                if not pf:
                    continue
                self._adb_su(f"cp /data/data/{VW_PACKAGE}/shared_prefs/{pf} /data/local/tmp/{pf}")
                r2 = subprocess.run(
                    ["adb", "pull", f"/data/local/tmp/{pf}", f"{local_tmp}/{pf}"],
                    capture_output=True, text=True, timeout=10,
                )
                local_pf = f"{local_tmp}/{pf}"
                if os.path.exists(local_pf):
                    with open(local_pf, "r", errors="replace") as f:
                        content = f.read()
                    # Check for vehicle-related content
                    keywords = ["90bf07c5", "702b3cc5", "vehicle", "garage",
                                "selected", "vin", "atlas", "buzz"]
                    hits = [kw for kw in keywords if kw.lower() in content.lower()]
                    if hits:
                        log.info("RN_STORAGE: MATCH [%s] keywords=%s content=%s",
                                 pf, hits, content[:500])
                    else:
                        log.debug("RN_STORAGE: [%s] no vehicle keywords (%d bytes)",
                                  pf, len(content))

            self.mqttc.publish(
                f"{MQTT_TOPIC_PREFIX}/rn_storage",
                json.dumps({"status": "ok", "msg": "See addon logs for results"}),
            )
        except Exception as e:
            log.error("RN_STORAGE: Failed: %s", e)

    def _switch_vehicle_rn(self, target_vid=None):
        """Switch the VW app to a different vehicle by modifying RN AsyncStorage
        and relaunching the app. This is more reliable than blind UI tapping."""
        if not target_vid:
            log.error("SWITCH: No target vehicle ID provided")
            return

        log.info("SWITCH: Attempting to switch to vehicle %s", target_vid[:16])

        import sqlite3 as pysqlite
        try:
            remote_db = f"/data/data/{VW_PACKAGE}/databases/RKStorage"
            local_db = "/tmp/vw_switch_RKStorage"

            # Pull DB locally, modify, push back
            self._adb_su(f"cp {remote_db} /data/local/tmp/RKStorage_sw")
            self._adb_su("chmod 644 /data/local/tmp/RKStorage_sw")
            subprocess.run(
                ["adb", "pull", "/data/local/tmp/RKStorage_sw", local_db],
                capture_output=True, timeout=15,
            )

            if not os.path.exists(local_db):
                log.error("SWITCH: Failed to pull RKStorage")
                return

            conn = pysqlite.connect(local_db)
            cur = conn.cursor()

            # List tables and find vehicle-related keys
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [r[0] for r in cur.fetchall()]
            log.info("SWITCH: DB tables: %s", tables)

            # Dump all keys that might relate to vehicles
            for table in tables:
                try:
                    cur.execute(f"SELECT * FROM [{table}]")
                    cols = [d[0] for d in cur.description]
                    rows = cur.fetchall()
                    for row in rows:
                        row_str = " | ".join(str(v)[:150] for v in row)
                        if any(kw in row_str.lower() for kw in
                               ["vehicle", "selected", "garage", "current",
                                "90bf07c5", "702b3cc5", "vin"]):
                            log.info("SWITCH: MATCH [%s] %s", table, row_str[:400])
                except Exception:
                    pass

            # Try updating known key patterns
            update_keys = [
                "selectedVehicleId", "selected_vehicle_id", "currentVehicleId",
                "@selectedVehicleId", "selectedVehicle", "activeVehicleId",
            ]
            updated = 0
            for table in tables:
                for key in update_keys:
                    try:
                        cur.execute(f"UPDATE [{table}] SET value=? WHERE key=?",
                                    (target_vid, key))
                        updated += cur.rowcount
                    except Exception:
                        pass
            conn.commit()
            log.info("SWITCH: Updated %d rows in local DB", updated)
            conn.close()

            # Push modified DB back to phone
            subprocess.run(
                ["adb", "push", local_db, "/data/local/tmp/RKStorage_sw"],
                capture_output=True, timeout=15,
            )
            self._adb_su(f"cp /data/local/tmp/RKStorage_sw {remote_db}")
            self._adb_su(f"chmod 660 {remote_db}")
            # Fix ownership (app uid)
            self._adb_su(f"chown $(stat -c %u:%g {remote_db.rsplit('/', 1)[0]}) {remote_db}")

            # Force-stop and relaunch the app
            log.info("SWITCH: Force-restarting VW app...")
            subprocess.run(
                ["adb", "shell", "am", "force-stop", VW_PACKAGE],
                capture_output=True, timeout=10,
            )
            time.sleep(3)
            subprocess.run(
                ["adb", "shell", "am", "start", "-n",
                 f"{VW_PACKAGE}/com.vw.myVW.activities.RoutingActivity"],
                capture_output=True, timeout=10,
            )
            time.sleep(10)

            # Reattach Frida
            log.info("SWITCH: Reattaching Frida after app restart...")
            try:
                self._attach_frida()
            except Exception as e:
                log.warning("SWITCH: Frida reattach failed: %s — will retry", e)
                time.sleep(5)
                try:
                    self._attach_frida()
                except Exception as e2:
                    log.error("SWITCH: Frida reattach failed again: %s", e2)

            # Wait for app to load and make API calls
            time.sleep(20)

            # Check if we got a token for the target vehicle
            target_token = self._get_valid_token(target_vid, vehicle_only=True)
            if target_token:
                log.info("SWITCH: SUCCESS — got token for %s", target_vid[:16])
                self.mqttc.publish(
                    f"{MQTT_TOPIC_PREFIX}/switch_vehicle",
                    json.dumps({"status": "success", "vehicle": target_vid}),
                )
            else:
                log.warning("SWITCH: No token for %s after restart", target_vid[:16])
                self.mqttc.publish(
                    f"{MQTT_TOPIC_PREFIX}/switch_vehicle",
                    json.dumps({"status": "no_token", "vehicle": target_vid}),
                )

        except Exception as e:
            log.error("SWITCH: Failed: %s", e)
            self.mqttc.publish(
                f"{MQTT_TOPIC_PREFIX}/switch_vehicle",
                json.dumps({"status": "error", "msg": str(e)}),
            )

    def _clear_app_data(self):
        """Clear VW app data to force fresh login."""
        try:
            log.info("CLEAR: Clearing VW app data...")
            subprocess.run(
                ["adb", "shell", "pm", "clear", VW_PACKAGE],
                capture_output=True, timeout=15,
            )
            log.info("CLEAR: App data cleared. Use auto_login to re-authenticate.")
            self.mqttc.publish(
                f"{MQTT_TOPIC_PREFIX}/clear_data",
                json.dumps({"status": "ok", "msg": "App data cleared"}),
            )
        except Exception as e:
            log.error("CLEAR: Failed: %s", e)

    def _dump_ui_xml(self):
        """Dump UI hierarchy via uiautomator and return parsed XML string."""
        import xml.etree.ElementTree as ET
        try:
            subprocess.run(
                ["adb", "shell", "uiautomator", "dump", "/data/local/tmp/ui.xml"],
                capture_output=True, text=True, timeout=15,
            )
            r = subprocess.run(
                ["adb", "shell", "cat", "/data/local/tmp/ui.xml"],
                capture_output=True, text=True, timeout=15,
            )
            return r.stdout.strip() if r.returncode == 0 else None
        except Exception as e:
            log.warning("UI_XML: dump failed: %s", e)
            return None

    def _find_ui_elements(self, xml_str, text=None, content_desc=None,
                          resource_id=None, class_name=None):
        """Find UI elements by attributes. Returns list of (cx, cy, bounds, attrs)."""
        import xml.etree.ElementTree as ET
        import re
        results = []
        if not xml_str:
            return results
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError as e:
            log.warning("UI_XML: parse error: %s", e)
            return results

        for node in root.iter("node"):
            attrs = node.attrib
            match = True
            if text and text.lower() not in attrs.get("text", "").lower():
                match = False
            if content_desc and content_desc.lower() not in attrs.get("content-desc", "").lower():
                match = False
            if resource_id and resource_id.lower() not in attrs.get("resource-id", "").lower():
                match = False
            if class_name and class_name not in attrs.get("class", ""):
                match = False
            if match and (text or content_desc or resource_id or class_name):
                bounds_str = attrs.get("bounds", "")
                m = re.match(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', bounds_str)
                if m:
                    x1, y1, x2, y2 = int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))
                    cx, cy = (x1 + x2) // 2, (y1 + y2) // 2
                    results.append((cx, cy, bounds_str, attrs))
        return results

    def _tap_element(self, xml_str, desc, text=None, content_desc=None,
                     resource_id=None, class_name=None, index=0):
        """Find element in UI XML and tap its center. Returns True if tapped."""
        elems = self._find_ui_elements(xml_str, text=text, content_desc=content_desc,
                                       resource_id=resource_id, class_name=class_name)
        if elems and index < len(elems):
            cx, cy, bounds, attrs = elems[index]
            log.info("AUTO_LOGIN: tap_element(%d,%d) %s [%s] text='%s'",
                     cx, cy, desc, bounds, attrs.get("text", "")[:50])
            subprocess.run(["adb", "shell", "input", "tap", str(cx), str(cy)],
                           capture_output=True, timeout=10)
            return True
        else:
            search = text or content_desc or resource_id or class_name
            log.warning("AUTO_LOGIN: element NOT FOUND: %s (search=%s, found=%d)",
                        desc, search, len(elems))
            return False

    def _auto_login(self):
        """Automated login flow: clear data → launch → fill WebView credentials.
        Uses uiautomator dump to find UI elements dynamically."""
        if not self.vw_email or not self.vw_password:
            log.error("AUTO_LOGIN: No credentials configured (vw_email/vw_password)")
            return

        def _tap(x, y, desc=""):
            log.info("AUTO_LOGIN: tap(%d, %d) %s", x, y, desc)
            subprocess.run(["adb", "shell", "input", "tap", str(x), str(y)],
                           capture_output=True, timeout=10)
            time.sleep(1.5)

        def _input_text(text, desc=""):
            log.info("AUTO_LOGIN: input_text [%s]", desc)
            escaped = text.replace(" ", "%s").replace("@", "\\@").replace("&", "\\&")
            subprocess.run(["adb", "shell", "input", "text", escaped],
                           capture_output=True, timeout=10)
            time.sleep(1)

        def _swipe(x1, y1, x2, y2, ms=300):
            subprocess.run(
                ["adb", "shell", "input", "swipe",
                 str(x1), str(y1), str(x2), str(y2), str(ms)],
                capture_output=True, timeout=10)
            time.sleep(1)

        def _get_activity():
            r = subprocess.run(
                ["adb", "shell", "dumpsys", "activity", "top"],
                capture_output=True, text=True, timeout=10)
            for line in r.stdout.split('\n'):
                if 'ACTIVITY' in line and VW_PACKAGE in line:
                    return line.strip()
            return "unknown"

        def _wait_for_activity(target, timeout=30):
            """Wait until a specific activity substring appears."""
            start = time.time()
            while time.time() - start < timeout:
                act = _get_activity()
                if target.lower() in act.lower():
                    return act
                time.sleep(2)
            return None

        def _log_ui_elements(xml_str, label=""):
            """Log all clickable/focusable elements for debugging."""
            if not xml_str:
                log.info("UI_DUMP[%s]: No XML available", label)
                return
            elems = self._find_ui_elements(xml_str, text="")
            # Log all elements with text or content-desc
            import xml.etree.ElementTree as ET
            import re
            try:
                root = ET.fromstring(xml_str)
                count = 0
                for node in root.iter("node"):
                    a = node.attrib
                    txt = a.get("text", "")
                    desc = a.get("content-desc", "")
                    rid = a.get("resource-id", "")
                    cls = a.get("class", "")
                    clickable = a.get("clickable", "false")
                    bounds = a.get("bounds", "")
                    if txt or desc or clickable == "true":
                        log.info("UI[%s] %s bounds=%s click=%s text='%s' desc='%s' id='%s'",
                                 label, cls.split(".")[-1] if cls else "",
                                 bounds, clickable, txt[:40], desc[:40], rid[:60])
                        count += 1
                        if count > 30:
                            log.info("UI[%s] ... (%d+ elements, truncated)", label, count)
                            break
            except Exception as e:
                log.warning("UI[%s] parse error: %s", label, e)

        try:
            log.info("AUTO_LOGIN: Starting automated login flow...")

            # Step 1: Clear app data
            log.info("AUTO_LOGIN: Step 1 — Clearing app data...")
            subprocess.run(
                ["adb", "shell", "pm", "clear", VW_PACKAGE],
                capture_output=True, timeout=15,
            )
            time.sleep(2)

            # Step 2: Wake screen
            log.info("AUTO_LOGIN: Step 2 — Waking screen...")
            subprocess.run(["adb", "shell", "input", "keyevent", "KEYCODE_WAKEUP"],
                           capture_output=True, timeout=10)
            time.sleep(1)
            _swipe(360, 1400, 360, 600, 300)  # Swipe up to dismiss lock screen
            time.sleep(2)

            # Step 3: Launch app fresh
            log.info("AUTO_LOGIN: Step 3 — Launching VW app fresh...")
            subprocess.run(
                ["adb", "shell", "am", "start", "-n",
                 f"{VW_PACKAGE}/com.vw.myVW.activities.RoutingActivity"],
                capture_output=True, timeout=10)
            time.sleep(8)  # Wait for splash/welcome screen

            activity = _get_activity()
            log.info("AUTO_LOGIN: After launch, activity: %s", activity)

            # Step 4: Navigate welcome/onboarding using UI element detection
            log.info("AUTO_LOGIN: Step 4 — Navigating welcome screen...")
            xml = self._dump_ui_xml()
            _log_ui_elements(xml, "welcome")

            # Try common button texts for welcome/onboarding
            tapped = False
            for btn_text in ["Let's Go", "Get Started", "Continue", "Next", "Accept",
                             "I Agree", "OK", "AGREE", "ACCEPT"]:
                if self._tap_element(xml, f"welcome:{btn_text}", text=btn_text):
                    tapped = True
                    time.sleep(3)
                    break
            if not tapped:
                # Fallback: tap bottom center where CTA usually is
                _tap(360, 1350, "bottom CTA fallback")
                time.sleep(3)

            # Handle permission dialogs (Android system)
            for attempt in range(3):
                xml = self._dump_ui_xml()
                _log_ui_elements(xml, f"permission_{attempt}")
                # Android permission dialog buttons
                perm_tapped = False
                for perm_text in ["While using the app", "Allow", "ALLOW",
                                  "While using", "Only this time"]:
                    if self._tap_element(xml, f"permission:{perm_text}", text=perm_text):
                        perm_tapped = True
                        time.sleep(2)
                        break
                # Also try resource-id for system permission buttons
                if not perm_tapped:
                    for rid in ["com.android.permissioncontroller:id/permission_allow_foreground_only_button",
                                "com.android.permissioncontroller:id/permission_allow_button",
                                "android:id/button1"]:
                        if self._tap_element(xml, f"perm_rid:{rid}", resource_id=rid):
                            perm_tapped = True
                            time.sleep(2)
                            break
                if not perm_tapped:
                    break  # No more permission dialogs

            # Step 5: Find and tap Log In button
            log.info("AUTO_LOGIN: Step 5 — Looking for login button...")
            xml = self._dump_ui_xml()
            _log_ui_elements(xml, "login_screen")

            login_tapped = False
            for btn_text in ["Log In", "Login", "Sign In", "LOG IN", "SIGN IN", "Sign in"]:
                if self._tap_element(xml, f"login:{btn_text}", text=btn_text):
                    login_tapped = True
                    break
            if not login_tapped:
                # Fallback
                _tap(360, 1350, "Log In fallback")

            # Wait for WebView (AzsCallbackActivity) to load
            log.info("AUTO_LOGIN: Waiting for OIDC WebView...")
            act = _wait_for_activity("AzsCallback", timeout=15)
            if act:
                log.info("AUTO_LOGIN: WebView loaded: %s", act)
            else:
                log.warning("AUTO_LOGIN: WebView didn't load, checking current activity...")
                activity = _get_activity()
                log.info("AUTO_LOGIN: Current: %s", activity)

            time.sleep(3)  # Let WebView content render

            # Step 6: Enter email in OIDC WebView
            log.info("AUTO_LOGIN: Step 6 — Entering email...")
            xml = self._dump_ui_xml()
            _log_ui_elements(xml, "webview_email")

            # Find email input field — try EditText class or input fields
            email_tapped = False
            for search in [
                {"class_name": "android.widget.EditText"},
                {"resource_id": "email"},
                {"resource_id": "username"},
                {"content_desc": "email"},
            ]:
                if self._tap_element(xml, "email field", **search):
                    email_tapped = True
                    break
            if not email_tapped:
                _tap(360, 550, "email field fallback")

            time.sleep(1)
            _input_text(self.vw_email, "email")
            time.sleep(1)

            # Try tapping Next/Continue button
            xml = self._dump_ui_xml()
            _log_ui_elements(xml, "after_email_input")
            next_tapped = False
            for btn_text in ["Next", "Continue", "NEXT", "CONTINUE", "Weiter"]:
                if self._tap_element(xml, f"next:{btn_text}", text=btn_text):
                    next_tapped = True
                    break
            if not next_tapped:
                # Try Enter key then fallback tap
                subprocess.run(["adb", "shell", "input", "keyevent", "KEYCODE_ENTER"],
                               capture_output=True, timeout=10)
            time.sleep(4)

            # Step 7: Enter password
            log.info("AUTO_LOGIN: Step 7 — Entering password...")
            xml = self._dump_ui_xml()
            _log_ui_elements(xml, "webview_password")

            pwd_tapped = False
            for search in [
                {"class_name": "android.widget.EditText"},
                {"resource_id": "password"},
                {"content_desc": "password"},
            ]:
                if self._tap_element(xml, "password field", **search):
                    pwd_tapped = True
                    break
            if not pwd_tapped:
                _tap(360, 550, "password field fallback")

            time.sleep(1)
            _input_text(self.vw_password, "password")
            time.sleep(1)

            # Submit login
            xml = self._dump_ui_xml()
            _log_ui_elements(xml, "after_password_input")
            submit_tapped = False
            for btn_text in ["Sign In", "Log In", "Login", "Submit",
                             "SIGN IN", "LOG IN", "Anmelden"]:
                if self._tap_element(xml, f"submit:{btn_text}", text=btn_text):
                    submit_tapped = True
                    break
            if not submit_tapped:
                subprocess.run(["adb", "shell", "input", "keyevent", "KEYCODE_ENTER"],
                               capture_output=True, timeout=10)

            log.info("AUTO_LOGIN: Waiting for OIDC redirect...")
            time.sleep(15)  # Wait for OIDC redirect + app load

            activity = _get_activity()
            log.info("AUTO_LOGIN: After sign-in, activity: %s", activity)

            # Step 8: Reattach Frida and wait for tokens
            log.info("AUTO_LOGIN: Step 8 — Reattaching Frida...")
            time.sleep(5)
            try:
                self._attach_frida()
            except Exception as e:
                log.warning("AUTO_LOGIN: Frida attach failed: %s, retrying...", e)
                time.sleep(5)
                try:
                    self._attach_frida()
                except Exception as e2:
                    log.error("AUTO_LOGIN: Frida attach failed again: %s", e2)

            # Wait for app to make API calls and capture tokens
            log.info("AUTO_LOGIN: Waiting 30s for app to load and make API calls...")
            time.sleep(30)

            # Check if we got a fresh token
            if self.global_token:
                log.info("AUTO_LOGIN: SUCCESS — got fresh token!")
                self.mqttc.publish(
                    f"{MQTT_TOPIC_PREFIX}/auto_login",
                    json.dumps({"status": "success", "msg": "Fresh token captured"}),
                )
            else:
                log.warning("AUTO_LOGIN: No token captured yet.")
                self.mqttc.publish(
                    f"{MQTT_TOPIC_PREFIX}/auto_login",
                    json.dumps({"status": "no_token",
                                "msg": "Login may have failed — check addon logs"}),
                )

        except Exception as e:
            log.error("AUTO_LOGIN: Failed: %s", e)
            self.mqttc.publish(
                f"{MQTT_TOPIC_PREFIX}/auto_login",
                json.dumps({"status": "error", "msg": str(e)}),
            )

    def _update_pif(self):
        """Run the Play Integrity fingerprint updater script."""
        log.info("Running PIF fingerprint updater...")
        try:
            result = subprocess.run(
                ["sh", "/opt/update_pif.sh", "--reboot"],
                capture_output=True, text=True, timeout=120,
            )
            for line in result.stdout.splitlines():
                log.info(line)
            if result.stderr:
                for line in result.stderr.splitlines():
                    log.warning("PIF stderr: %s", line)
            status = "success" if result.returncode == 0 else "failed"
            self.mqttc.publish(
                f"{MQTT_TOPIC_PREFIX}/pif_update",
                json.dumps({"status": status, "output": result.stdout[-500:]}),
            )
        except subprocess.TimeoutExpired:
            log.error("PIF update timed out")
            self.mqttc.publish(
                f"{MQTT_TOPIC_PREFIX}/pif_update",
                json.dumps({"status": "timeout"}),
            )
        except Exception as e:
            log.error("PIF update error: %s", e)

    # ── Token management ────────────────────────────────────────────
    def _store_token_from_header(self, token, url):
        """Store an access token captured from an Authorization header."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return
            payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload))

            expiry = datetime.fromtimestamp(claims["exp"])
            self.user_id = claims.get("sub", self.user_id)
            vehicle_id = claims.get("tid")  # vehicle-scoped tokens have tid

            with self._lock:
                if vehicle_id:
                    old = self.tokens.get(vehicle_id, {}).get("token", "")
                    if old != token:
                        self.tokens[vehicle_id] = {"token": token, "expiry": expiry}
                        if vehicle_id not in self.vehicle_ids:
                            self.vehicle_ids.append(vehicle_id)
                        self._last_token_time = datetime.now()
                        log.info("Vehicle token updated: %s (exp %s)", vehicle_id[:8], expiry.strftime("%H:%M"))
                else:
                    if self.global_token != token:
                        self.global_token = token
                        self.global_expiry = expiry
                        self._last_token_time = datetime.now()
                        log.info("Global token updated (exp %s)", expiry.strftime("%H:%M"))
        except Exception as e:
            log.debug("Token parse error: %s", e)

    def _store_tokens_from_response(self, body_str):
        """Parse and store tokens from an OIDC token response."""
        try:
            body = json.loads(body_str)
        except json.JSONDecodeError:
            return

        with self._lock:
            if "refresh_token" in body:
                self.refresh_token = body["refresh_token"]
                rt_exp = body.get("refresh_expires_in", 2592000)
                log.info("Refresh token captured (expires in %dd)", rt_exp // 86400)
            if "id_token" in body:
                self.id_token = body["id_token"]
            if "access_token" in body:
                self._store_token_from_header(body["access_token"], "token_response")

        # Publish the full token dict for CarConnectivity connector consumption
        # This is the key integration point — the connector's MQTTTokenSession
        # subscribes to this topic and uses these tokens for API calls
        token_relay = {}
        for key in ("access_token", "refresh_token", "id_token", "token_type",
                     "expires_in", "scope"):
            if key in body:
                token_relay[key] = body[key]
        if token_relay.get("access_token"):
            self.mqttc.publish(
                f"{MQTT_TOPIC_PREFIX}/token_relay",
                json.dumps(token_relay),
                retain=True,
            )
            log.info("Published full token to %s/token_relay for connector", MQTT_TOPIC_PREFIX)

    # ── Vehicle data parsing & MQTT publishing ────────────────────
    def _parse_and_publish_vehicle_data(self, url, body_str, method="GET"):
        """Parse API response and publish structured data to per-topic MQTT."""
        try:
            body = json.loads(body_str)
        except json.JSONDecodeError:
            return

        short = url.replace(BASE_URL, "")

        # Extract vehicle ID from URL
        m = re.search(r"/vehicle/([0-9a-f-]{36})", url)
        vid = m.group(1) if m else "unknown"

        data = body.get("data", body)

        # ── Garage (vehicle list) ──
        if "/account/v1/garage" in url:
            if "vehicles" in (data or {}):
                vehicles = []
                for v in data["vehicles"]:
                    vehicles.append({
                        "vin": v.get("vin"),
                        "vehicleId": v.get("vehicleId"),
                        "nickname": v.get("vehicleNickName"),
                        "model": v.get("modelName"),
                    })
                self.mqttc.publish(
                    f"{MQTT_TOPIC_PREFIX}/garage",
                    json.dumps(vehicles), retain=True,
                )
                log.info("Published garage data (%d vehicles)", len(vehicles))
            return

        # ── RVS vehicle status ──
        if "/rvs/v1/vehicle/" in url and data:
            with self._lock:
                self.vehicle_data.setdefault(vid, {})["rvs"] = data

            # Power status → range, fuel
            ps = data.get("powerStatus")
            if ps:
                self.mqttc.publish(
                    f"{MQTT_TOPIC_PREFIX}/{vid}/power",
                    json.dumps({
                        "cruise_range": ps.get("cruiseRange"),
                        "range_units": ps.get("cruiseRangeUnits", "KM"),
                        "fuel_percent": ps.get("fuelPercentRemaining"),
                    }), retain=True,
                )

            # Odometer
            if "currentMileage" in data:
                self.mqttc.publish(
                    f"{MQTT_TOPIC_PREFIX}/{vid}/odometer",
                    json.dumps({"km": data["currentMileage"]}), retain=True,
                )

            # Location
            loc = data.get("location") or data.get("lastParkedLocation")
            if loc and loc.get("latitude") and loc.get("longitude"):
                self.mqttc.publish(
                    f"{MQTT_TOPIC_PREFIX}/{vid}/location",
                    json.dumps({
                        "latitude": loc["latitude"],
                        "longitude": loc["longitude"],
                        "timestamp": loc.get("timestamp"),
                    }), retain=True,
                )

            # Exterior status → doors, windows, lights, lock
            ext = data.get("exteriorStatus")
            if ext:
                self.mqttc.publish(
                    f"{MQTT_TOPIC_PREFIX}/{vid}/doors",
                    json.dumps({
                        "door_status": ext.get("doorStatus"),
                        "door_lock_status": ext.get("doorLockStatus"),
                        "secure": ext.get("secure"),
                    }), retain=True,
                )
                if ext.get("windowStatus"):
                    self.mqttc.publish(
                        f"{MQTT_TOPIC_PREFIX}/{vid}/windows",
                        json.dumps(ext["windowStatus"]), retain=True,
                    )
                if ext.get("lightStatus"):
                    self.mqttc.publish(
                        f"{MQTT_TOPIC_PREFIX}/{vid}/lights",
                        json.dumps(ext["lightStatus"]), retain=True,
                    )

            # Also publish full raw RVS for anything we missed
            self.mqttc.publish(
                f"{MQTT_TOPIC_PREFIX}/{vid}/rvs_raw",
                json.dumps(data),
            )
            log.info("Published RVS data for %s", vid[:8])
            return

        # ── EV climate ──
        if "/ev/v1/vehicle/" in url and "/climate/" in url and data:
            with self._lock:
                self.vehicle_data.setdefault(vid, {})["climate"] = data

            climate_out = {}
            csr = data.get("climateStatusReport")
            if csr:
                climate_out["state"] = csr.get("climateStatusInd")
                climate_out["remaining_min"] = csr.get("remainingclimatizationTimeMin")
            cs = data.get("climateSettings")
            if cs:
                tt = cs.get("targetTemperature", {})
                climate_out["target_temp"] = tt.get("temperature")
                climate_out["temp_unit"] = tt.get("unit")
                climate_out["seat_heating"] = {
                    k: v for k, v in cs.items() if "seat" in k.lower() or "Seat" in k
                }

            self.mqttc.publish(
                f"{MQTT_TOPIC_PREFIX}/{vid}/climate",
                json.dumps(climate_out), retain=True,
            )
            log.info("Published climate data for %s", vid[:8])
            return

        # ── EV charging ──
        if ("/ev/v1/vehicle/" in url and "/charg" in url) or "/charging/" in url:
            if data:
                with self._lock:
                    self.vehicle_data.setdefault(vid, {})["charging"] = data
                self.mqttc.publish(
                    f"{MQTT_TOPIC_PREFIX}/{vid}/charging",
                    json.dumps(data), retain=True,
                )
                log.info("Published charging data for %s", vid[:8])
            return

        # ── Lock/unlock response ──
        if "/lockunlock/" in url:
            action = "lock" if method == "PUT" else "lock_status"
            self.mqttc.publish(
                f"{MQTT_TOPIC_PREFIX}/{vid}/lock_response",
                json.dumps(data),
            )
            return

        # ── RRS privileges/capabilities ──
        if "/rrs/v1/privileges/" in url and data:
            self.mqttc.publish(
                f"{MQTT_TOPIC_PREFIX}/{vid}/capabilities",
                json.dumps(data), retain=True,
            )
            return

        # ── Catch-all: publish raw to api_response ──
        self.mqttc.publish(
            f"{MQTT_TOPIC_PREFIX}/api_response",
            json.dumps({"url": short, "method": method, "body": body_str[:4000]}),
        )

    # ── Frida callbacks ─────────────────────────────────────────────
    def _on_message(self, message, data):
        if message["type"] != "send":
            if message["type"] == "error":
                log.error("Frida error: %s", message.get("description", ""))
            return

        payload = message["payload"]
        msg_type = payload.get("type")

        if msg_type == "status":
            log.info("Frida: %s", payload["msg"])

        elif msg_type == "token_response":
            self._store_tokens_from_response(payload["body"])
            self._publish_tokens()

        elif msg_type == "auth_header":
            self._store_token_from_header(payload["token"], payload["url"])
            m = re.search(r"/vehicle/([0-9a-f-]{36})", payload["url"])
            if m:
                vid = m.group(1)
                with self._lock:
                    if vid not in self.vehicle_ids:
                        self.vehicle_ids.append(vid)
            # Publish to token_relay on token CHANGE only (dedup)
            with self._lock:
                token = self.global_token
                refresh = self.refresh_token
                id_tok = self.id_token
            if token and token != getattr(self, '_last_relayed_token', None):
                self._last_relayed_token = token
                relay_data = {"access_token": token, "token_type": "bearer"}
                if refresh:
                    relay_data["refresh_token"] = refresh
                if id_tok:
                    relay_data["id_token"] = id_tok
                self.mqttc.publish(
                    f"{MQTT_TOPIC_PREFIX}/token_relay",
                    json.dumps(relay_data),
                    retain=True,
                )
                self._publish_tokens()
                log.info("Published token_relay (new token)")

        elif msg_type == "full_traffic":
            # Log ALL VW domain traffic for remote start discovery
            url = payload.get("url", "")
            method = payload.get("method", "?")
            status = payload.get("status", "?")
            req_body = payload.get("requestBody", "")
            resp_body = payload.get("responseBody", "")
            log.info("═══ TRAFFIC ═══ %s %s → %s", method, url, status)
            if req_body:
                log.info("  REQ BODY: %s", req_body[:2000])
            if resp_body:
                log.info("  RESP BODY: %s", resp_body[:2000])
            req_hdrs = payload.get("requestHeaders", {})
            if req_hdrs:
                # Log interesting headers (skip boring ones)
                skip = {'host', 'accept-encoding', 'connection', 'user-agent'}
                interesting = {k: v for k, v in req_hdrs.items() if k.lower() not in skip}
                if interesting:
                    log.info("  REQ HDRS: %s", json.dumps(interesting, indent=None)[:1000])
            # Also publish to MQTT for easy viewing
            self.mqttc.publish(
                f"{MQTT_TOPIC_PREFIX}/traffic",
                json.dumps({
                    "method": method, "url": url, "status": status,
                    "requestBody": (req_body or "")[:2000],
                    "responseBody": (resp_body or "")[:2000],
                }),
            )

        elif msg_type == "api_response":
            self._parse_and_publish_vehicle_data(
                payload["url"], payload["body"], payload.get("method", "GET")
            )

    # ── Frida connection ────────────────────────────────────────────
    def _attach_frida(self):
        """Attach to the VW app via USB."""
        log.info("Looking for USB device...")
        self.device = frida.get_usb_device(timeout=10)
        log.info("Device: %s", self.device.name)

        pid = None
        try:
            for app in self.device.enumerate_applications():
                if app.identifier == VW_PACKAGE:
                    pid = app.pid
                    break
        except Exception:
            pass

        if not pid:
            try:
                for proc in self.device.enumerate_processes():
                    if VW_PACKAGE in (proc.name, getattr(proc, 'identifier', '')):
                        pid = proc.pid
                        break
            except Exception as e:
                log.warning("enumerate_processes failed (phone still booting?): %s", e)
                pass

        if not pid:
            log.warning("VW app not running. Attempting to launch...")
            try:
                pid = self.device.spawn([VW_PACKAGE])
                self.device.resume(pid)
                time.sleep(3)
            except Exception as e:
                log.error("Cannot start VW app: %s", e)
                return False

        log.info("Attaching to PID %d...", pid)
        self.session = self.device.attach(pid)
        self.session.on("detached", self._on_detached)

        self.script = self.session.create_script(FRIDA_SCRIPT)
        self.script.on("message", self._on_message)
        self.script.load()
        log.info("Frida script loaded — hooks active")
        return True

    def _on_detached(self, reason, crash):
        log.warning("Frida detached: %s", reason)
        if not self._running:
            return
        # Auto-reattach loop
        for attempt in range(5):
            log.info("Reattach attempt %d/5 in 10s...", attempt + 1)
            time.sleep(10)
            try:
                if self._attach_frida():
                    return
            except Exception as e:
                log.error("Reattach failed: %s", e)
        log.error("Gave up reattaching. Publish MQTT offline.")
        self.mqttc.publish(f"{MQTT_TOPIC_PREFIX}/status", "error", retain=True)

    # ── Auto re-login ──────────────────────────────────────────────
    def _auto_relogin(self):
        """Run the auto-login script when the app needs re-authentication."""
        if not all([self.vw_email, self.vw_password, self.vw_spin]):
            log.warning("Auto-login credentials not configured — manual login required")
            self.mqttc.publish(
                f"{MQTT_TOPIC_PREFIX}/alert",
                json.dumps({"alert": "login_required", "msg": "VW app needs re-login. Credentials not configured for auto-login."}),
                retain=True,
            )
            return False

        log.info("Running auto re-login...")
        try:
            result = subprocess.run(
                [sys.executable, "vw_auto_login.py",
                 "--email", self.vw_email,
                 "--password", self.vw_password,
                 "--spin", self.vw_spin],
                capture_output=True, text=True, timeout=120,
                cwd=os.path.dirname(os.path.abspath(__file__)),
            )
            log.info("Auto-login output: %s", result.stdout[-200:] if result.stdout else "(empty)")
            if result.returncode == 0:
                log.info("Auto re-login completed")
                return True
            else:
                log.error("Auto re-login failed: %s", result.stderr[-200:] if result.stderr else "(empty)")
                return False
        except Exception as e:
            log.error("Auto re-login error: %s", e)
            return False

    # ── Keep-alive loop ─────────────────────────────────────────────
    def _keepalive_loop(self):
        """Every 20 minutes, wake the app to force a token refresh.
        If tokens haven't refreshed after waking, attempt re-login."""
        no_token_count = 0

        while self._running:
            time.sleep(1200)  # 20 minutes
            with self._lock:
                needs_refresh = False
                all_expired = True
                for vid, t in self.tokens.items():
                    if datetime.now() > t["expiry"] - timedelta(minutes=5):
                        needs_refresh = True
                    else:
                        all_expired = False
                if self.global_expiry:
                    if datetime.now() > self.global_expiry - timedelta(minutes=5):
                        needs_refresh = True
                    else:
                        all_expired = False
                has_any_token = bool(self.tokens) or self.global_token

            if needs_refresh or not has_any_token:
                log.info("Tokens expiring/missing, waking app for refresh...")
                self._wake_app()
                time.sleep(30)  # Wait for app to make API calls

                # Check if we got fresh tokens
                with self._lock:
                    still_expired = True
                    for vid, t in self.tokens.items():
                        if datetime.now() < t["expiry"] - timedelta(minutes=5):
                            still_expired = False
                    if self.global_expiry and datetime.now() < self.global_expiry - timedelta(minutes=5):
                        still_expired = False

                if still_expired and has_any_token:
                    no_token_count += 1
                    log.warning("No fresh tokens after wake (attempt %d)", no_token_count)
                    if no_token_count >= 3:
                        log.info("Persistent auth failure — attempting auto re-login")
                        self._auto_relogin()
                        no_token_count = 0
                        time.sleep(15)
                        self._wake_app()  # Re-trigger after login
                else:
                    no_token_count = 0

            # ── Proactive token validation ──
            # Make a lightweight test API call to verify the token actually works
            # against VW's servers (catches revoked tokens, PI failures, etc.)
            with self._lock:
                test_vids = list(self.tokens.keys())
            if test_vids:
                test_vid = test_vids[0]
                test_token = self._get_valid_token(test_vid)
                if test_token:
                    test_url = f"{BASE_URL}/rvs/v1/vehicle/{test_vid}"
                    test_headers = {**VW_API_HEADERS, "Authorization": f"Bearer {test_token}"}
                    if self.user_id:
                        test_headers["x-user-id"] = self.user_id
                    try:
                        req = Request(test_url, method="GET", headers=test_headers)
                        with urlopen(req, timeout=15) as resp:
                            resp.read()
                        log.debug("Token validation: OK")
                    except HTTPError as e:
                        if e.code in (401, 403):
                            log.warning("Token validation failed (%d) — waking app for refresh", e.code)
                            self._wake_app()
                        else:
                            log.debug("Token validation: HTTP %d (non-auth, ignoring)", e.code)
                    except Exception:
                        pass  # network glitch, ignore

            # ── PIF health check ──
            # If no fresh token in 45+ minutes and we haven't rebooted recently,
            # assume Play Integrity is broken → update fingerprint + reboot phone
            pif_status = "healthy"
            if self._last_token_time:
                token_age_min = (datetime.now() - self._last_token_time).total_seconds() / 60
                cooldown_ok = (
                    self._pif_reboot_cooldown is None
                    or (datetime.now() - self._pif_reboot_cooldown).total_seconds() > 7200  # 2hr cooldown
                )
                if token_age_min > 45 and cooldown_ok:
                    pif_status = "degraded"
                    log.warning("PIF HEALTH: No fresh token in %.0f min — triggering PIF update + reboot", token_age_min)
                    self._pif_reboot_cooldown = datetime.now()
                    threading.Thread(target=self._update_pif, daemon=True).start()
                elif token_age_min > 45:
                    pif_status = "cooldown"
                    log.info("PIF HEALTH: Token stale (%.0f min) but in reboot cooldown", token_age_min)

            # Publish health status
            self.mqttc.publish(
                f"{MQTT_TOPIC_PREFIX}/pif_health",
                json.dumps({
                    "status": pif_status,
                    "last_token_age_min": round((datetime.now() - self._last_token_time).total_seconds() / 60, 1) if self._last_token_time else None,
                    "last_token_at": self._last_token_time.isoformat() if self._last_token_time else None,
                }),
                retain=True,
            )

            # Always publish current state
            self._publish_tokens()

    # ── Main ────────────────────────────────────────────────────────
    def run(self):
        # Handle SIGTERM gracefully (Docker sends this on container stop)
        def _handle_sigterm(signum, frame):
            log.info("Received SIGTERM — shutting down gracefully")
            self._running = False
        signal.signal(signal.SIGTERM, _handle_sigterm)

        self._setup_mqtt()

        # Ensure phone screen stays on while USB-connected (critical for ADB taps)
        try:
            subprocess.run(
                ["adb", "shell", "settings", "put", "global",
                 "stay_on_while_plugged_in", "3"],
                capture_output=True, timeout=5,
            )
            log.info("Set stay_on_while_plugged_in=3 (screen always on via USB)")
        except Exception:
            pass

        # Diagnostic: check ADB state before Frida
        try:
            adb_out = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=10)
            log.info("ADB DIAG: devices=%s", adb_out.stdout.strip().replace('\n', ' | '))
        except Exception as e:
            log.warning("ADB DIAG: adb devices failed: %s", e)

        frida_ok = False
        try:
            frida_ok = self._attach_frida()
        except Exception as e:
            log.warning("Frida attach failed (phone unavailable?): %s", e)

        if not frida_ok:
            log.warning("Running WITHOUT Frida — MQTT commands available but no token capture")
        else:
            # Start keepalive thread only if Frida is connected
            t = threading.Thread(target=self._keepalive_loop, daemon=True)
            t.start()

        log.info("=" * 60)
        log.info("VW Token Relay running%s", " (NO FRIDA)" if not frida_ok else "")
        log.info("  MQTT: %s:%d", self.mqtt_host, self.mqtt_port)
        log.info("  Topics:")
        log.info("    %s/tokens       — current token state (retained)", MQTT_TOPIC_PREFIX)
        log.info("    %s/status       — online/offline (retained)", MQTT_TOPIC_PREFIX)
        log.info("    %s/api_response — captured API responses", MQTT_TOPIC_PREFIX)
        log.info("    %s/cmd/lock     — send vehicle_id to lock", MQTT_TOPIC_PREFIX)
        log.info("    %s/cmd/unlock   — send vehicle_id to unlock", MQTT_TOPIC_PREFIX)
        log.info("    %s/cmd/climate_start  — send vehicle_id to start climate", MQTT_TOPIC_PREFIX)
        log.info("    %s/cmd/climate_stop   — send vehicle_id to stop climate", MQTT_TOPIC_PREFIX)
        log.info("    %s/cmd/remote_start   — send vehicle_id for remote engine start (ICE)", MQTT_TOPIC_PREFIX)
        log.info("    %s/cmd/remote_start_stop — send vehicle_id to stop remote start", MQTT_TOPIC_PREFIX)
        log.info("    %s/pif_health         — PI status: healthy/degraded/cooldown (retained)", MQTT_TOPIC_PREFIX)
        log.info("    %s/cmd/update_pif     — refresh Play Integrity fingerprint", MQTT_TOPIC_PREFIX)
        log.info("    %s/cmd/wake_app       — force app refresh", MQTT_TOPIC_PREFIX)
        log.info("    %s/cmd/vehicle_status — send vehicle_id", MQTT_TOPIC_PREFIX)
        log.info("=" * 60)

        try:
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            log.info("Shutting down (KeyboardInterrupt)...")
        except SystemExit as e:
            log.info("Shutting down (SystemExit code=%s)...", e.code)
        except Exception as e:
            log.error("Main loop crashed: %s", e, exc_info=True)
        finally:
            self._running = False
            log.info("Relay main loop exited — cleaning up")

        if self.mqttc:
            self.mqttc.publish(f"{MQTT_TOPIC_PREFIX}/status", "offline", retain=True)
            self.mqttc.disconnect()


def main():
    p = argparse.ArgumentParser(description="VW myVW Token Relay")
    p.add_argument("--mqtt-host", required=True, help="MQTT broker IP (e.g. your HA IP)")
    p.add_argument("--mqtt-port", type=int, default=1883)
    p.add_argument("--mqtt-user", default=None)
    p.add_argument("--mqtt-pass", default=None)
    p.add_argument("--vw-email", default=os.environ.get("VW_EMAIL"),
                   help="VW account email (or VW_EMAIL env var)")
    p.add_argument("--vw-password", default=os.environ.get("VW_PASSWORD"),
                   help="VW account password (or VW_PASSWORD env var)")
    p.add_argument("--vw-spin", default=os.environ.get("VW_SPIN"),
                   help="VW S-PIN (or VW_SPIN env var)")
    args = p.parse_args()

    VWTokenRelay(
        mqtt_host=args.mqtt_host,
        mqtt_port=args.mqtt_port,
        mqtt_user=args.mqtt_user,
        mqtt_pass=args.mqtt_pass,
        vw_email=args.vw_email,
        vw_password=args.vw_password,
        vw_spin=args.vw_spin,
    ).run()


if __name__ == "__main__":
    try:
        main()
    except SystemExit as e:
        log.info("Process exiting (code=%s)", e.code)
        sys.exit(e.code)
    except Exception as e:
        log.error("FATAL unhandled exception: %s", e, exc_info=True)
        sys.exit(1)
