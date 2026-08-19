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
        return Java.perform(function () {
            var KeyStore = Java.use('java.security.KeyStore');
            var ks = KeyStore.getInstance('AndroidKeyStore');
            ks.load(null);
            var aliases = ks.aliases();
            var result = [];
            while (aliases.hasMoreElements()) {
                result.push(aliases.nextElement().toString());
            }
            return JSON.stringify(result);
        });
    },

    // Sign data with the VW pairing key from Android KeyStore
    // dataBase64: base64-encoded bytes to sign
    // alias: KeyStore alias (discovered via listKeystoreAliases)
    signWithKeystore: function (dataBase64, alias) {
        return Java.perform(function () {
            var KeyStore = Java.use('java.security.KeyStore');
            var Signature = Java.use('java.security.Signature');
            var Base64 = Java.use('android.util.Base64');

            var ks = KeyStore.getInstance('AndroidKeyStore');
            ks.load(null);

            if (!ks.containsAlias(alias)) {
                return JSON.stringify({ error: 'alias_not_found', alias: alias });
            }

            var entry = ks.getEntry(alias, null);
            var privateKey = Java.cast(entry, Java.use('java.security.KeyStore$PrivateKeyEntry')).getPrivateKey();

            var sig = Signature.getInstance('SHA256withECDSA');
            sig.initSign(privateKey);
            var dataBytes = Base64.decode(dataBase64, 0);
            sig.update(dataBytes);
            var sigBytes = sig.sign();
            var sigB64 = Base64.encodeToString(sigBytes, 2); // NO_WRAP
            return JSON.stringify({ signature: sigB64 });
        });
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
            self._wake_app()
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
        elif cmd == "update_pif":
            threading.Thread(target=self._update_pif, daemon=True).start()
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
    def _get_valid_token(self, vehicle_id=None):
        """Get a valid token, preferring vehicle-scoped if available."""
        with self._lock:
            if vehicle_id and vehicle_id in self.tokens:
                t = self.tokens[vehicle_id]
                if datetime.now() < t["expiry"]:
                    return t["token"]
            if self.global_token and self.global_expiry and datetime.now() < self.global_expiry:
                return self.global_token
        return None

    def _api_call(self, method, url_or_vid):
        """Make a direct API call using captured token."""
        vid = url_or_vid.strip()
        if not vid.startswith("http"):
            # Assume it's a vehicle ID — fetch status
            url = f"{BASE_URL}/rvs/v1/vehicle/{vid}"
        else:
            url = vid

        # Extract vehicle ID from URL
        m = re.search(r"/vehicle/([0-9a-f-]{36})", url)
        vid = m.group(1) if m else None

        token = self._get_valid_token(vid)
        if not token:
            self.mqttc.publish(
                f"{MQTT_TOPIC_PREFIX}/error",
                json.dumps({"error": "no_valid_token", "msg": "Token expired — wake the app"}),
            )
            log.warning("No valid token for API call")
            return

        headers = {**VW_API_HEADERS, "Authorization": f"Bearer {token}"}
        if self.user_id:
            headers["x-user-id"] = self.user_id

        req = Request(url, method=method, headers=headers)
        try:
            with urlopen(req, timeout=15) as resp:
                body = resp.read().decode()
            self.mqttc.publish(
                f"{MQTT_TOPIC_PREFIX}/response/vehicle_status",
                body,
            )
            log.info("API call success: %s (%d bytes)", url[:80], len(body))
        except HTTPError as e:
            err = e.read().decode("utf-8", errors="replace")
            log.error("API call failed (%d): %s", e.code, err[:200])
            self.mqttc.publish(
                f"{MQTT_TOPIC_PREFIX}/error",
                json.dumps({"error": f"http_{e.code}", "url": url, "body": err[:500]}),
            )

    def _api_lock(self, vehicle_id, lock=True):
        """Send lock/unlock command."""
        vid = vehicle_id.strip()
        token = self._get_valid_token(vid)
        if not token:
            self.mqttc.publish(
                f"{MQTT_TOPIC_PREFIX}/error",
                json.dumps({"error": "no_valid_token", "msg": "Token expired — wake the app"}),
            )
            return

        url = f"{BASE_URL}/lockunlock/v1/vehicle/{vid}"
        body = json.dumps({"lock": lock}).encode()
        headers = {**VW_API_HEADERS, "Authorization": f"Bearer {token}"}
        if self.user_id:
            headers["x-user-id"] = self.user_id

        req = Request(url, data=body, method="PUT", headers=headers)
        try:
            with urlopen(req, timeout=15) as resp:
                result = resp.read().decode()
            action = "lock" if lock else "unlock"
            self.mqttc.publish(
                f"{MQTT_TOPIC_PREFIX}/response/{action}",
                result,
            )
            log.info("%s success: %s", action.upper(), result[:200])
        except HTTPError as e:
            err = e.read().decode("utf-8", errors="replace")
            log.error("Lock/unlock failed (%d): %s", e.code, err[:200])

    def _api_climate(self, vehicle_id, start=True):
        """Send climate start/stop command."""
        vid = vehicle_id.strip()
        token = self._get_valid_token(vid)
        if not token:
            self.mqttc.publish(
                f"{MQTT_TOPIC_PREFIX}/error",
                json.dumps({"error": "no_valid_token", "msg": "Token expired — wake the app"}),
            )
            return

        action = "start" if start else "stop"
        url = f"{BASE_URL}/ev/v1/vehicle/{vid}/pretripclimate/{action}"
        headers = {**VW_API_HEADERS, "Authorization": f"Bearer {token}"}
        if self.user_id:
            headers["x-user-id"] = self.user_id

        req = Request(url, data=b"", method="POST", headers=headers)
        try:
            with urlopen(req, timeout=15) as resp:
                result = resp.read().decode()
            self.mqttc.publish(
                f"{MQTT_TOPIC_PREFIX}/response/climate",
                result,
            )
            log.info("CLIMATE %s success: %s", action.upper(), result[:200])
        except HTTPError as e:
            err = e.read().decode("utf-8", errors="replace")
            log.error("Climate %s failed (%d): %s", action, e.code, err[:200])
            self.mqttc.publish(
                f"{MQTT_TOPIC_PREFIX}/error",
                json.dumps({"error": f"climate_{e.code}", "action": action, "body": err[:500]}),
            )

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
                aliases_json = self.script.exports_sync.list_keystore_aliases()
                aliases = json.loads(aliases_json)
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
                        result = json.loads(self.script.exports_sync.sign_with_keystore(data_b64, alias))
                        if "signature" in result:
                            self._keystore_alias = alias
                            log.info("Found working KeyStore alias: %s", alias)
                            return result["signature"]
                    log.error("No working KeyStore alias found")
                    return None
                else:
                    log.error("No KeyStore aliases found")
                    return None

            result = json.loads(self.script.exports_sync.sign_with_keystore(data_b64, self._keystore_alias))
            if "error" in result:
                log.error("KeyStore signing failed: %s", result)
                self._keystore_alias = None  # Reset for rediscovery
                return None
            return result["signature"]
        except Exception as e:
            log.error("Frida RPC signing failed: %s", e)
            return None

    def _get_pairing_data(self, vehicle_id):
        """Get pairing data for a vehicle from the API."""
        token = self._get_valid_token(vehicle_id)
        if not token:
            return None

        url = f"{BASE_URL}/pair/v1/vehicle/{vehicle_id}"
        headers = {**VW_API_HEADERS, "Authorization": f"Bearer {token}"}
        if self.user_id:
            headers["x-user-id"] = self.user_id

        req = Request(url, method="GET", headers=headers)
        try:
            with urlopen(req, timeout=15) as resp:
                body = json.loads(resp.read().decode())
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
        except HTTPError as e:
            log.error("Get pairing failed (%d): %s", e.code, e.read().decode()[:200])
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
        log.info("═══ REMOTE START ═══ vehicle=%s", vid)

        if not self.vw_spin:
            self.mqttc.publish(f"{MQTT_TOPIC_PREFIX}/error",
                json.dumps({"error": "no_spin", "msg": "S-PIN not configured — required for remote start"}))
            return

        token = self._get_valid_token(vid)
        if not token:
            self.mqttc.publish(f"{MQTT_TOPIC_PREFIX}/error",
                json.dumps({"error": "no_valid_token", "msg": "Token expired — wake the app first"}))
            return

        headers = {**VW_API_HEADERS, "Authorization": f"Bearer {token}"}
        if self.user_id:
            headers["x-user-id"] = self.user_id

        # Step 1: Get pairing data
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
        req = Request(challenge_url, method="GET", headers=headers)
        try:
            with urlopen(req, timeout=15) as resp:
                challenge_data = json.loads(resp.read().decode())
        except HTTPError as e:
            log.error("SPIN challenge failed (%d): %s", e.code, e.read().decode()[:200])
            self.mqttc.publish(f"{MQTT_TOPIC_PREFIX}/error",
                json.dumps({"error": "spin_challenge_failed", "code": e.code}))
            return

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
        req = Request(check_url, data=check_body, method="POST", headers=headers)
        try:
            with urlopen(req, timeout=15) as resp:
                check_data = json.loads(resp.read().decode())
        except HTTPError as e:
            err = e.read().decode("utf-8", errors="replace")
            log.error("SPIN check failed (%d): %s", e.code, err[:200])
            self.mqttc.publish(f"{MQTT_TOPIC_PREFIX}/error",
                json.dumps({"error": "spin_check_failed", "code": e.code, "body": err[:500]}))
            return

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

        req = Request(rst_url, data=rst_body, method="POST", headers=headers)
        try:
            with urlopen(req, timeout=30) as resp:
                rst_data = json.loads(resp.read().decode())
        except HTTPError as e:
            err = e.read().decode("utf-8", errors="replace")
            log.error("Remote start POST failed (%d): %s", e.code, err[:500])
            self.mqttc.publish(f"{MQTT_TOPIC_PREFIX}/error",
                json.dumps({"error": "rst_post_failed", "code": e.code, "body": err[:500]}))
            return

        log.info("RST: POST response: %s", json.dumps(rst_data)[:500])

        # Extract correlationId for polling
        correlation_id = rst_data.get("data", {}).get("correlationId")
        if not correlation_id:
            # Response might be the full data directly
            self.mqttc.publish(f"{MQTT_TOPIC_PREFIX}/{vid}/remote_start",
                json.dumps(rst_data), retain=False)
            log.info("RST: No correlationId in response — published raw result")
            return

        # Step 8: Poll for result
        log.info("RST Step 8: Polling for result (correlationId=%s)...", correlation_id)
        self.mqttc.publish(f"{MQTT_TOPIC_PREFIX}/{vid}/remote_start",
            json.dumps({"status": "pending", "correlationId": correlation_id}), retain=False)

        poll_url = f"{BASE_URL}/history/v1/vehicle/{vid}/correlationId/{correlation_id}/ro/"
        for attempt in range(12):  # Poll up to 2 minutes
            time.sleep(10)
            req = Request(poll_url, method="GET", headers=headers)
            try:
                with urlopen(req, timeout=15) as resp:
                    poll_data = json.loads(resp.read().decode())
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
            except HTTPError as e:
                if e.code == 404:
                    log.debug("RST poll %d: not ready yet (404)", attempt + 1)
                else:
                    log.error("RST poll failed (%d): %s", e.code, e.read().decode()[:200])
            except Exception as e:
                log.error("RST poll error: %s", e)

        log.warning("RST: Polling timed out after %d attempts", 12)
        self.mqttc.publish(f"{MQTT_TOPIC_PREFIX}/{vid}/remote_start",
            json.dumps({"status": "timeout", "correlationId": correlation_id}), retain=False)

    def _api_remote_start_stop(self, vehicle_id):
        """Stop a running remote start."""
        vid = vehicle_id.strip()
        token = self._get_valid_token(vid)
        if not token:
            self.mqttc.publish(f"{MQTT_TOPIC_PREFIX}/error",
                json.dumps({"error": "no_valid_token", "msg": "Token expired"}))
            return

        url = f"{BASE_URL}/rst/v1/vehicle/{vid}"
        headers = {**VW_API_HEADERS, "Authorization": f"Bearer {token}"}
        if self.user_id:
            headers["x-user-id"] = self.user_id

        req = Request(url, method="DELETE", headers=headers)
        try:
            with urlopen(req, timeout=15) as resp:
                result = resp.read().decode()
            log.info("RST STOP success: %s", result[:200])
            self.mqttc.publish(f"{MQTT_TOPIC_PREFIX}/{vid}/remote_start",
                json.dumps({"status": "stopped"}), retain=False)
        except HTTPError as e:
            err = e.read().decode("utf-8", errors="replace")
            log.error("RST stop failed (%d): %s", e.code, err[:200])

    # ── Wake the VW app to trigger token refresh ────────────────────
    def _wake_app(self):
        """Force-restart the VW app to trigger fresh API calls and token capture.
        Just 'am start' on an already-running app doesn't trigger new traffic."""
        try:
            # Wake screen first
            subprocess.run(
                ["adb", "shell", "input", "keyevent", "KEYCODE_WAKEUP"],
                capture_output=True, timeout=5,
            )
            time.sleep(1)
            # Force-stop the app so relaunch triggers fresh API calls
            subprocess.run(
                ["adb", "shell", "am", "force-stop", VW_PACKAGE],
                capture_output=True, timeout=10,
            )
            time.sleep(2)
            # Relaunch
            subprocess.run(
                ["adb", "shell", "am", "start", "-n",
                 f"{VW_PACKAGE}/com.vw.myVW.activities.RoutingActivity"],
                capture_output=True, timeout=10,
            )
            log.info("Force-restarted VW app — waiting for token capture")
            # Need to re-attach Frida since the app got a new PID
            time.sleep(5)
            try:
                self._attach_frida()
            except Exception as e:
                log.error("Failed to reattach Frida after app restart: %s", e)
        except Exception as e:
            log.error("Failed to wake app: %s", e)

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
            for proc in self.device.enumerate_processes():
                if VW_PACKAGE in (proc.name, getattr(proc, 'identifier', '')):
                    pid = proc.pid
                    break

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

        if not self._attach_frida():
            log.error("Could not attach to VW app")
            return

        # Start keepalive thread
        t = threading.Thread(target=self._keepalive_loop, daemon=True)
        t.start()

        log.info("=" * 60)
        log.info("VW Token Relay running")
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
