# VW Token Relay — Home Assistant Add-on

Captures Play Integrity tokens and OAuth credentials from the VW myVW app via Frida over USB, and relays them via MQTT for [CarConnectivity](https://github.com/tillsteinbach/CarConnectivity).

## Why this exists

VW's North American API (US/CA) requires every request to carry a Play Integrity–attested token. The official myVW app passes Google's device attestation check; a headless Python connector cannot. This add-on bridges the gap: a rooted Android phone runs the real myVW app, Frida hooks intercept the attested tokens in real-time, and MQTT delivers them to CarConnectivity or Home Assistant automations. Without this (or a similar relay), the [VW NA connector](https://github.com/zackcornelius/CarConnectivity-connector-volkswagen-na) cannot authenticate.

## Architecture

```
Phone (VW app + Frida) ──USB/ADB──▸ This add-on ──MQTT──▸ Home Assistant / CarConnectivity
```

A rooted Android phone runs the official myVW app. Frida hooks OkHttp3's `BridgeInterceptor` to capture OAuth tokens in real-time. Tokens are published to MQTT, where CarConnectivity or HA automations consume them.

## Requirements

- Rooted Android phone with:
  - Magisk + Zygisk enabled
  - Play Integrity Fix (PIF) module (chiteroman, osm0sis, or KOWX712 variant)
  - Shamiko module for root hiding
  - myVW app installed and logged in
  - USB debugging enabled
  - Frida server running (`frida-server-16.5.9-android-arm64`)
- USB connection from phone to HA host
- Mosquitto MQTT broker on HA

## Features

### Token Relay
- Captures Play Integrity tokens, OAuth access, refresh, and ID tokens from the VW app via Frida hooks
- Publishes all tokens to MQTT (`vw/token_relay`) with retain for CarConnectivity consumption
- 20-minute keepalive cycle wakes the app to force token refresh
- Auto-recovers from Frida crashes, ADB disconnects, and app restarts

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
3. Install this add-on from the [add-on repository](https://github.com/danielsza/carconnectivity-addon)
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
3. **Install PIF module** — Magisk → Modules → Install Play Integrity Fix
4. **Install Shamiko** — Magisk → Modules → Install Shamiko
5. **Configure DenyList** — Magisk Settings → Enable Zygisk, Enable DenyList. Add `com.google.android.gms` and the VW app.
6. **Install Frida server** — push to `/data/local/tmp/frida-server`, chmod +x, start with su
7. **Install myVW** — sideload APK, log in, grant all permissions
8. **Enable USB debugging** — Developer Options → USB Debugging
9. **Keep screen on** — `adb shell settings put global stay_on_while_plugged_in 3`
10. **Verify PI** — test with SPIC or YASNAC; should show DEVICE_INTEGRITY

## Reference Setup (known-good)

| Component | Version / Detail |
|-----------|-----------------|
| Phone | Motorola Moto G Pure (720×1600, arm64) |
| Android | 11 (stock) |
| Magisk | 28.1+ with Zygisk enabled |
| PIF module | chiteroman Play Integrity Fix (autopif variant) |
| Shamiko | Latest (root-hide for GMS + VW app) |
| Frida server | 16.5.9-android-arm64 |
| myVW package | `com.vw.carnet.releaseca` (Canada) |
| PI verdict | DEVICE_INTEGRITY (verified with SPIC) |
| HA host | HP mini PC (x86, USB connection to phone) |
| MQTT broker | Mosquitto (HA add-on) |

## Tested Vehicles

| Vehicle | Platform | TSP | Features tested |
|---------|----------|-----|----------------|
| 2025 VW ID. Buzz 1st Edition | MEB/EV | WCT | lock, unlock, climate, charging, status |
| 2024 VW Atlas | MQB/ICE | ATC | lock, unlock, climate, remote start, status |

## Region Notes

Tested on Canadian endpoint (`b-h-s.spr.ca00.p.con-veh.net`). The US endpoint uses the same API — change the base URL to `b-h-s.spr.us00.p.con-veh.net`. No code changes needed.

## Troubleshooting

- **"No tokens received"** — check that Frida server is running on the phone (`adb shell su -c "ps | grep frida"`), the VW app is logged in, and USB debugging is enabled.
- **Tokens go stale after a few hours** — PIF fingerprint may have been revoked. The add-on auto-recovers, but if `vw/pif_health` stays `critical`, manually update the PIF module's fingerprint list.
- **Remote start fails with "device pairing required"** — first-time remote start requires pairing the phone with VW's server. Use `vw/cmd/ui_remote_start` to trigger the pairing flow through the app UI.
- **"Media Storage keeps stopping" dialog** — common on Moto G Pure. The relay auto-dismisses this, but if it persists, clear Media Storage data in Android settings.
- **Screen stays locked after reboot** — the add-on unlocks the screen automatically (wake → dismiss-keyguard → swipe → home). If this fails, ensure the phone has no PIN/pattern lock set.
