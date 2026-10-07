# VW Token Relay — Home Assistant Add-on

Captures Play Integrity tokens and OAuth credentials from the VW myVW app via Frida over USB, and relays them via MQTT for [CarConnectivity](https://github.com/tillsteinbach/CarConnectivity).

## Why this exists

VW's North American API requires every request to carry a Play Integrity–attested token. This is already enforced in the US and is expected to roll out to Canada. The official myVW app passes Google's device attestation check; a headless Python connector cannot. This add-on bridges the gap: a rooted Android phone runs the real myVW app, Frida hooks intercept the attested tokens in real-time, and MQTT delivers them to CarConnectivity or Home Assistant automations. Without this (or a similar relay), the [VW NA connector](https://github.com/zackcornelius/CarConnectivity-connector-volkswagen-na) cannot authenticate.

**Note:** Tested on the Canadian endpoint. As of October 2026, the phone achieves **MEETS_STRONG_INTEGRITY** — the highest Play Integrity level — on a Moto G15 Power running LineageOS 23.2 (Android 16) with Magisk 30.7, using the device's own fingerprint (no keybox needed). This should satisfy both the Canadian and US endpoints. See [Play Integrity Result](#play-integrity-result) below.

## Architecture

```
Phone (VW app + Frida) ──USB/ADB──▸ This add-on ──MQTT──▸ Home Assistant / CarConnectivity
```

A rooted Android phone runs the official myVW app. Frida's native `Interceptor.attach` hooks BoringSSL's `SSL_write`/`SSL_read` at the C level to capture OAuth tokens from HTTP traffic. ALPN negotiation is forced to HTTP/1.1 for parseable traffic. This approach is **GC-safe on Android 16** — no ART method structs are modified, avoiding the SIGSEGV crashes that occur with Java-level `.implementation` hooks. Tokens are published to MQTT, where CarConnectivity or HA automations consume them.

## Requirements

- Rooted Android phone with:
  - Magisk (28.1+)
  - ReZygisk module (replaces Magisk's built-in Zygisk)
  - Shamiko module (hides root from Google Play Services and the VW app)
  - Play Integrity Fix (PIF) module — configured with the device's own fingerprint (extracted before rooting)
  - myVW app installed and logged in
  - USB debugging enabled
  - Frida server running (`frida-server-17.22.2-android-arm64` recommended — must match your `frida-tools` version)
- USB connection from phone to HA host
- Mosquitto MQTT broker on HA

## Features

### Token Relay
- Captures Play Integrity tokens, OAuth access, refresh, and ID tokens from the VW app via Frida hooks
- Publishes all tokens to MQTT (`vw/token_relay`) with retain for CarConnectivity consumption
- 20-minute keepalive cycle wakes the app to force token refresh
- Auto-recovers from Frida crashes, silent detaches, ADB disconnects, and app restarts

### Vehicle Commands (via MQTT)
- **Lock/Unlock:** `vw/cmd/lock` / `vw/cmd/unlock` — send vehicle UUID as payload
- **Climate start/stop:** `vw/cmd/climate_start` / `vw/cmd/climate_stop`
- **Remote start (ICE):** `vw/cmd/ui_remote_start` / `vw/cmd/ui_remote_start_stop` — drives the app's UI to start/stop the engine (see below)
- **Vehicle status:** `vw/cmd/vehicle_status` — queries vehicle data
- **Wake app:** `vw/cmd/wake_app` — force token refresh

### Remote Start (ICE/hybrid vehicles)

Two approaches were tested:

| Approach | How it works | Status |
|----------|-------------|--------|
| **Native API** | Two-challenge SPIN flow → roToken → POST/DELETE to `/rst/v1`. | Blocked — `/climateControl/check` returns 403 without a server-side captcha that only the VW app's native `SpinService.createCaptcha()` can create. Dead end for pure API. |
| **UI-driven** | Relay drives the VW app's own Remote Start button via uiautomator. Handles SPIN entry, device pairing, and result detection. | **Working** — this is the only viable approach. |

The UI-driven path is the only way to do remote start. The relay navigates the VW app's UI automatically: vehicle dashboard → "Remote start" → "Start/Stop" → enter SPIN → confirm.

### Vehicle Data (published to MQTT)
- `vw/{vehicle_id}/power` — fuel/charge level, range
- `vw/{vehicle_id}/odometer` — mileage
- `vw/{vehicle_id}/location` — GPS coordinates
- `vw/{vehicle_id}/doors` — door/window/lock status
- `vw/{vehicle_id}/climate` — climatization state
- `vw/{vehicle_id}/charging` — EV charging data

### Play Integrity Auto-Fix
- Monitors token freshness (PIF health check every ~20 min)
- If tokens go stale (>45 min), escalates through three levels:
  1. **Level 1:** Updates PIF fingerprint + reboots phone with boot-loop protection
  2. **Level 2:** Removes and re-adds the Google account on the phone (fixes stale Finsky credentials that cause PI to drop to BASIC). Requires `google_email` and `google_password` in config.
  3. **Level 3+:** Notifies user, keeps retrying PIF updates
- Unlocks screen after reboot (wake + dismiss-keyguard + swipe + home)
- Publishes health status to `vw/pif_health` (healthy/degraded/cooldown/critical)
- Google account refresh status published to `vw/google_refresh`

### Error Notifications
- Publishes errors to `vw/error`, `vw/pif_health`, `vw/pif_update`, `vw/auto_login`
- Designed to pair with HA automations for iOS/Android push notifications

## Frida Agent — Native SSL Hooks (v3.1)

The Frida agent captures tokens by hooking BoringSSL at the native (C) level rather than at Java. This is critical for Android 16 compatibility:

| Approach | How | Android 16 |
|----------|-----|------------|
| Java `.implementation` | Replaces ART method entry points | **Crashes** — GC walks corrupted `CodeInfo` metadata → SIGSEGV at ~20s |
| `Java.registerClass` | Registers new Java class via JNI | **Crashes** — null pointer in `art::JNI::CallObjectMethod` at ~4s |
| **Native `Interceptor.attach`** | Patches first instruction of C functions | **Works** — no ART structs modified, GC-safe |

The agent hooks three BoringSSL functions:

- **`SSL_set_alpn_protos`** — Strips `h2` from ALPN negotiation, forcing HTTP/1.1 so traffic is parseable as plain text
- **`SSL_write`** — Captures outgoing HTTP requests (method, path, Host, Authorization headers)
- **`SSL_read`** — Captures incoming HTTP responses, handles chunked transfer encoding and gzip decompression via native zlib

Java is used **only** for RPC exports (`readSharedPrefs`, `signWithKeystore`) via `Java.performNow` — one-shot JNI calls that don't modify ART method structs.

The agent is compiled with `frida-compile` to bundle `frida-java-bridge` (required since Frida 17 decoupled it from core). Frida globals (`Module`, etc.) are accessed via `Process.enumerateModules()` to avoid shadowing by the bundler.

## Quickstart

1. Root your Android phone and pass Play Integrity (see Phone Setup Guide below)
2. Connect the phone via USB to your Home Assistant host
3. Install this add-on from the [add-on repository](https://github.com/danielsza/ha-vw-token-relay)
4. Configure MQTT credentials and VW account details
5. Start the add-on — tokens should appear on `vw/token_relay` within 2 minutes
6. Point your CarConnectivity config at the MQTT token source

## Configuration

Add-on settings (Settings → Add-ons → VW Token Relay → Configuration):

| Option | Description |
|--------|-------------|
| `mqtt_host` | MQTT broker hostname (default: `core-mosquitto`) |
| `mqtt_port` | MQTT broker port (default: `1883`) |
| `mqtt_user` | MQTT username |
| `mqtt_pass` | MQTT password |
| `mqtt_topic` | Base MQTT topic (default: `vw/token_relay`) |
| `vw_package` | VW app package name (default: `com.vw.carnet.releaseca` for Canada) |
| `base_url` | VW API base URL |
| `vw_username` | VW account email (for auto-login after app crash) |
| `vw_password` | VW account password |
| `vw_spin` | Vehicle S-PIN (for remote start, lock/unlock) |
| `google_email` | Google account email on phone (for auto-refresh when PI drops) |
| `google_password` | Google account password (for auto-refresh when PI drops) |
| `log_level` | Log verbosity: info, debug, warning, error |

## Phone Setup Guide

1. **Unlock bootloader** — `fastboot oem unlock`
2. **Root with Magisk** — flash patched boot.img via fastboot
3. **Install ReZygisk** — Magisk → Modules → Install ReZygisk (replaces Magisk's built-in Zygisk)
4. **Install Shamiko** — Magisk → Modules → Install Shamiko. Hides root from Google Play Services and the VW app via DenyList.
5. **Install PIF module** — Magisk → Modules → Install Play Integrity Fix. Configure it with the device's own fingerprint (extract from stock build.prop before unlocking the bootloader)
6. **Configure DenyList** — Magisk Settings → Enable DenyList. Add `com.google.android.gms` and the VW app.
7. **Install Frida server** — download `frida-server-17.22.2-android-arm64` (or `-arm` for 32-bit) from [Frida releases](https://github.com/frida/frida/releases). Push to `/data/local/tmp/frida-server`, chmod +x. The add-on starts it automatically via ADB.

> **MediaTek devices (e.g., Moto G15 Power):** The bootloader can be unlocked using [kaeru](https://github.com/R0rt1z2/kaeru). See the [XDA kaeru thread](https://xdaforums.com/t/kaeru-arbitrary-code-execution-on-mediatek-bootloaders.4729227/) for device-specific guides. After bootloader unlock, flash a custom ROM like LineageOS for best results.

> **Android 16 note:** Frida 17+ decoupled the Java bridge from core — the agent uses `frida-compile` to bundle `frida-java-bridge` as an ESM import. Native SSL hooks (`Interceptor.attach` on BoringSSL) are used instead of Java-level `.implementation` hooks to avoid ART GC crashes (SIGSEGV in `CodeInfo::DecodeGcMasksOnly`). This is handled automatically by the add-on.
8. **Install myVW** — sideload APK, log in, grant all permissions
9. **Enable USB debugging** — Developer Options → USB Debugging
10. **Keep screen on** — `adb shell settings put global stay_on_while_plugged_in 3`
11. **Verify PI** — test with SPIC (`com.henrikherzig.playintegritychecker`); must show `MEETS_DEVICE_INTEGRITY` or higher. BASIC alone may not be sufficient — VW US requires DEVICE, and VW Canada may enforce it as well. With the device's own fingerprint, MEETS_STRONG_INTEGRITY is achievable — no keybox needed. If PI drops to BASIC after a while, remove and re-add the Google account on the phone (stale credentials cause Finsky to fall back to basic-only mode).

## Reference Setup (known-good)

| Component | Version / Detail |
|-----------|-----------------|
| Phone | Motorola Moto G15 Power (`lamu`, MediaTek, arm64) |
| OS | LineageOS 23.2 (Android 16, SDK 36) |
| Root | Magisk v30.7 |
| Zygisk | ReZygisk (replaces Magisk's built-in Zygisk) |
| Hide root | Shamiko (hides root from GMS and VW app) |
| PIF module | Play Integrity Fix — device's own fingerprint (extracted from stock before rooting) |
| Frida server | 17.22.2-android-arm64 |
| Frida agent | v3.1 — native SSL hooks via `Interceptor.attach` (GC-safe on Android 16) |
| myVW package | `com.vw.carnet.releaseca` (Canada) |
| PI verdict | **MEETS_STRONG_INTEGRITY** |
| HA host | Home Assistant OS on HP mini PC (x86, USB connection to phone) |
| MQTT broker | Mosquitto (HA add-on) |

### Previous Setup

The relay was originally developed on a Moto G Pure (XT2163-4, `ellis`, armeabi-v7a, Android 12) with Frida 16.5.9. That device was bricked during bootloader experiments. The current Moto G15 Power uses a MediaTek SoC — bootloader unlock was achieved using [kaeru](https://github.com/R0rt1z2/kaeru) (an ARMv7 payload for MediaTek LK bootloaders). See the [XDA thread](https://xdaforums.com/t/kaeru-arbitrary-code-execution-on-mediatek-bootloaders.4729227/) for guides on MTK bootloader unlocking.

## Tested Vehicles

| Vehicle | Platform | TSP | Features tested |
|---------|----------|-----|----------------|
| 2025 VW ID. Buzz 1st Edition | MEB/EV | WCT | lock, unlock, climate, charging, status |
| 2024 VW Atlas | MQB/ICE | ATC | lock, unlock, climate, remote start, status |

## Play Integrity Result

![SPIC showing MEETS_STRONG_INTEGRITY](https://raw.githubusercontent.com/danielsza/ha-vw-token-relay/main/docs/spic-strong-integrity.png)

**MEETS_STRONG_INTEGRITY** achieved on a rooted Moto G15 Power (LineageOS 23.2 / Android 16) with no keybox. Key factors:

1. **Device's own fingerprint** — extracted from the phone's stock firmware before unlocking the bootloader. No autopif rotation, no Canary fingerprint — the real device fingerprint passes PI natively.
2. **No keybox needed** — neither hardware nor software keybox is required. Tricky Store is not used.
3. **Fresh Google account credentials** — stale Google credentials cause Finsky to throw `IntegrityException` and fall back to basic-only mode. If PI drops to BASIC, remove the Google account and re-add it.
4. **ReZygisk + Shamiko + PIF** — Shamiko hides root from Google Play Services and the VW app. No Tricky Store needed. DenyList enabled with `com.google.android.gms` and the VW app added.
5. **MTK bootloader unlock via kaeru** — required for Moto G15 Power (MediaTek SoC). See [kaeru on GitHub](https://github.com/R0rt1z2/kaeru).

## Region Notes

Tested on Canadian endpoint (`b-h-s.spr.ca00.p.con-veh.net`). The US endpoint uses the same API — change the base URL to `b-h-s.spr.us00.p.con-veh.net`. No code changes needed.

## Troubleshooting

- **"No tokens received"** — check that Frida server is running on the phone (`adb shell su -c "ps | grep frida"`), the VW app is logged in, and USB debugging is enabled.
- **Tokens go stale after a few hours** — PIF fingerprint may have been revoked or expired. The add-on monitors this, but if `vw/pif_health` stays `critical`, check the PIF module configuration.
- **Remote start fails with "device pairing required"** — first-time remote start requires pairing the phone with VW's server. Use `vw/cmd/ui_remote_start` to trigger the pairing flow through the app UI.
- **"Media Storage keeps stopping" dialog** — common on Moto G Pure. The relay auto-dismisses this, but if it persists, clear Media Storage data in Android settings.
- **Screen stays locked after reboot** — the add-on unlocks the screen automatically (wake → dismiss-keyguard → swipe → home). If this fails, ensure the phone has no PIN/pattern lock set.
- **SIGSEGV crash ~20s after Frida attach (Android 16)** — this is the ART GC crash caused by Java-level `.implementation` hooks. The v3.1 agent avoids this entirely with native SSL hooks. If you see this, ensure you're running v1.28.3+ of the add-on.
- **`Module.findExportByName is not a function`** — frida-compile's bundler shadows Frida's `Module` global. Fixed in v1.28.3 by using `Process.enumerateModules()` instead.
- **`Java is not defined` (Frida 17+)** — Frida 17 decoupled the Java bridge. The add-on uses `frida-compile` to bundle it automatically. If you see this error, the compiled agent isn't being loaded — check the build log.
