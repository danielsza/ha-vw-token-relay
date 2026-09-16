# VW Token Relay — Home Assistant Add-on

Captures Play Integrity tokens and OAuth credentials from the VW myVW app via Frida over USB, and relays them via MQTT for [CarConnectivity](https://github.com/tillsteinbach/CarConnectivity).

## Why this exists

VW's North American API requires every request to carry a Play Integrity–attested token. This is already enforced in the US and is expected to roll out to Canada. The official myVW app passes Google's device attestation check; a headless Python connector cannot. This add-on bridges the gap: a rooted Android phone runs the real myVW app, Frida hooks intercept the attested tokens in real-time, and MQTT delivers them to CarConnectivity or Home Assistant automations. Without this (or a similar relay), the [VW NA connector](https://github.com/zackcornelius/CarConnectivity-connector-volkswagen-na) cannot authenticate.

**Note:** Tested on the Canadian endpoint. As of September 2026, the phone achieves **MEETS_STRONG_INTEGRITY** — the highest Play Integrity level — with a software keybox and Pixel 9a Canary fingerprint. This should satisfy both the Canadian and US endpoints. See [Play Integrity Result](#play-integrity-result) below.

## Architecture

```
Phone (VW app + Frida) ──USB/ADB──▸ This add-on ──MQTT──▸ Home Assistant / CarConnectivity
```

A rooted Android phone runs the official myVW app. Frida hooks OkHttp3's `BridgeInterceptor` to capture Play Integrity and OAuth tokens in real-time. Tokens are published to MQTT, where CarConnectivity or HA automations consume them.

## Requirements

- Rooted Android phone with:
  - Magisk (28.1+)
  - ReZygisk module (replaces Magisk's built-in Zygisk)
  - Play Integrity Fix (PIF) module — osm0sis variant with autopif fingerprint rotation
  - Tricky Store module (software keybox sufficient — no hardware keybox needed)
  - myVW app installed and logged in
  - USB debugging enabled
  - Frida server running (`frida-server-16.5.9-android-arm64` or `android-arm` for 32-bit firmware)
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
- If tokens go stale (>45 min), automatically:
  1. Updates the PIF fingerprint (runs the module's built-in autopif script)
  2. Reboots the phone with boot-loop protection (skips if uptime < 30 min)
  3. Unlocks the screen after reboot (wake + dismiss-keyguard + swipe + home)
  4. Wakes the VW app and waits for fresh tokens
- Publishes health status to `vw/pif_health` (healthy/degraded/cooldown/critical)
- Only notifies the user after 2+ consecutive auto-fix attempts fail

### Error Notifications
- Publishes errors to `vw/error`, `vw/pif_health`, `vw/pif_update`, `vw/auto_login`
- Designed to pair with HA automations for iOS/Android push notifications

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
| `log_level` | Log verbosity: info, debug, warning, error |

## Phone Setup Guide

1. **Unlock bootloader** — `fastboot oem unlock`
2. **Root with Magisk** — flash patched boot.img via fastboot
3. **Install ReZygisk** — Magisk → Modules → Install ReZygisk (replaces Magisk's built-in Zygisk)
4. **Install PIF module** — Magisk → Modules → Install Play Integrity Fix (osm0sis variant with autopif)
5. **Install Tricky Store** — Magisk → Modules → Install Tricky Store (software keybox is sufficient)
6. **Configure DenyList** — Magisk Settings → Enable DenyList. Add `com.google.android.gms` and the VW app.
7. **Install Frida server** — push to `/data/local/tmp/frida-server`, chmod +x, start with su. Use the `arm64` or `arm` binary matching your device's ABI (check `ro.product.cpu.abilist`).
8. **Install myVW** — sideload APK, log in, grant all permissions
9. **Enable USB debugging** — Developer Options → USB Debugging
10. **Keep screen on** — `adb shell settings put global stay_on_while_plugged_in 3`
11. **Verify PI** — test with SPIC (`com.henrikherzig.playintegritychecker`); must show `MEETS_DEVICE_INTEGRITY` or higher. BASIC alone may not be sufficient — VW US requires DEVICE, and VW Canada may enforce it as well. With the Pixel 9a Canary fingerprint + software keybox, MEETS_STRONG_INTEGRITY is achievable. If PI drops to BASIC after a while, remove and re-add the Google account on the phone (stale credentials cause Finsky to fall back to basic-only mode).

## Reference Setup (known-good)

| Component | Version / Detail |
|-----------|-----------------|
| Phone | Motorola Moto G Pure XT2163-4 (`ellis`, 720×1600, arm64) |
| Android | 12 (upgraded from stock 11 — PI did not pass on 11) |
| Magisk | 28.1+ |
| ReZygisk | Latest (replaces Magisk's built-in Zygisk) |
| PIF module | osm0sis Play Integrity Fix v18.0-lsposed with autopif fingerprint rotation |
| Tricky Store | Latest (software keybox — no hardware keybox needed) |
| Frida server | 16.5.9-android-arm (32-bit — Moto G Pure is armeabi-v7a only) |
| myVW package | `com.vw.carnet.releaseca` (Canada) |
| PI verdict | **MEETS_STRONG_INTEGRITY** (verified with SPIC — see screenshot below) |
| PIF fingerprint | Pixel 9a (`tegu_beta`) Canary — `google/tegu_beta/tegu:CANARY/ZP11.260717.006/16004061:user/release-keys` |
| HA host | HP mini PC (x86, USB connection to phone) |
| MQTT broker | Mosquitto (HA add-on) |

## Tested Vehicles

| Vehicle | Platform | TSP | Features tested |
|---------|----------|-----|----------------|
| 2025 VW ID. Buzz 1st Edition | MEB/EV | WCT | lock, unlock, climate, charging, status |
| 2024 VW Atlas | MQB/ICE | ATC | lock, unlock, climate, remote start, status |

## Play Integrity Result

![SPIC showing MEETS_STRONG_INTEGRITY](https://raw.githubusercontent.com/danielsza/ha-vw-token-relay/main/docs/spic-strong-integrity.png)

**MEETS_STRONG_INTEGRITY** achieved on a rooted Moto G Pure with a software keybox. Key factors:

1. **Pixel 9a Canary fingerprint** — `google/tegu_beta/tegu:CANARY/ZP11.260717.006/16004061:user/release-keys` with `DEVICE_INITIAL_SDK_INT=32` and `SECURITY_PATCH=2026-08-05`
2. **Fresh Google account credentials** — stale Google credentials cause Finsky to throw `IntegrityException` and fall back to basic-only mode. If PI drops to BASIC, remove the Google account and re-add it.
3. **ReZygisk + Tricky Store + PIF** — no Shamiko needed. DenyList enabled but empty (not required for these modules).

Previously achieved BASIC_INTEGRITY only (see `docs/spic-basic-integrity.png` for comparison). The upgrade to STRONG was achieved by switching from a Pixel 6 Canary fingerprint to Pixel 9a Canary and refreshing the Google account credentials on the phone.

## Region Notes

Tested on Canadian endpoint (`b-h-s.spr.ca00.p.con-veh.net`). The US endpoint uses the same API — change the base URL to `b-h-s.spr.us00.p.con-veh.net`. No code changes needed.

## Troubleshooting

- **"No tokens received"** — check that Frida server is running on the phone (`adb shell su -c "ps | grep frida"`), the VW app is logged in, and USB debugging is enabled.
- **Tokens go stale after a few hours** — PIF fingerprint may have been revoked. The add-on auto-recovers, but if `vw/pif_health` stays `critical`, manually update the PIF module's fingerprint list.
- **Remote start fails with "device pairing required"** — first-time remote start requires pairing the phone with VW's server. Use `vw/cmd/ui_remote_start` to trigger the pairing flow through the app UI.
- **"Media Storage keeps stopping" dialog** — common on Moto G Pure. The relay auto-dismisses this, but if it persists, clear Media Storage data in Android settings.
- **Screen stays locked after reboot** — the add-on unlocks the screen automatically (wake → dismiss-keyguard → swipe → home). If this fails, ensure the phone has no PIN/pattern lock set.
