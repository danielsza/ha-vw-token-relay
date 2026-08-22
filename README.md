# VW Token Relay — Home Assistant Add-on

Captures VW myVW app OAuth tokens via Frida over USB and relays them via MQTT for CarConnectivity Play Integrity bypass.

## Architecture

```
Phone (VW app + Frida) --USB/ADB--> This add-on --MQTT--> Home Assistant / CarConnectivity
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
- Captures OAuth access, refresh, and ID tokens from the VW app via Frida hooks
- Publishes tokens to MQTT (`vw/token_relay`) with retain for CarConnectivity consumption
- 20-minute keepalive cycle wakes the app to force token refresh
- Auto-recovers from Frida crashes, ADB disconnects, and app restarts

### Vehicle Commands (via MQTT)
- **Lock/Unlock:** `vw/cmd/lock` / `vw/cmd/unlock` — send vehicle UUID as payload
- **Climate start/stop:** `vw/cmd/climate_start` / `vw/cmd/climate_stop`
- **Remote start (ICE):** `vw/cmd/ui_remote_start` / `vw/cmd/ui_remote_start_stop` — drives the app's UI to start/stop the engine. Handles SPIN entry, device pairing, and result detection automatically.
- **Vehicle status:** `vw/cmd/vehicle_status` — queries vehicle data
- **Wake app:** `vw/cmd/wake_app` — force token refresh

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

## Tested Vehicles

- 2025 VW ID. Buzz (MEB/EV, TSP=WCT) — lock, unlock, climate, charging, status
- 2024 VW Atlas (MQB/ICE, TSP=ATC) — lock, unlock, climate, remote start, status

## Tested on Canadian endpoint (`b-h-s.spr.ca00.p.con-veh.net`). Should work on US endpoint with base URL change.
