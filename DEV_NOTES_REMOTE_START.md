# Remote Start (RST) — Dev Notes

## Overview

Remote start on the 2024 Atlas (ICE/MQB/ATC platform) requires an encrypted SPIN
payload sent via the ATC (Automotive Telematics Cloud) API. Unlike the ID. Buzz
(MEB/EV platform) which uses simpler climate control, the Atlas RST flow involves:

- XTEA encryption of SPIN + timestamps + captcha
- Device pairing (one-time, per-device)
- Server-side captcha creation (triggered by navigating the VW app to the vehicle)
- ECDSA signing of the encrypted payload

## Two Approaches

### 1. API-Only (partially working, captcha blocked)

**Flow:**
1. GET challenge → SHA-512(challenge + SPIN) → spinHash
2. POST /ss/.../session with {idToken, spinHash, tsp:"ATC"} → carnetVehicleToken
3. GET fresh challenge for /check
4. POST /ss/.../climateControl/check with {spinHash} → roToken
5. POST /rst/v1/vehicle/{vid} with XTEA-encrypted payload

**Problem:** Step 4 returns 403 because the captcha (SpinService) is a server-side
resource that must be created by the VW app navigating to the vehicle. The API-only
approach cannot create the captcha — the app's React Native bridge calls
`SpinService.createCaptcha()` which is a native Android method that sets up the
server-side state. Without it, `/check` always returns 403.

**Status:** Dead end for now. Steps 1-3 work perfectly; step 4 is blocked.

### 2. UI-Driven (current approach)

**Flow:** Drive the VW app's own "Remote start" button via uiautomator, letting the
app handle captcha creation internally.

**MQTT commands:**
- `vw/cmd/ui_remote_start` — payload = vehicle_id
- `vw/cmd/ui_remote_start_stop` — payload = vehicle_id

**Implementation:** `_ui_remote_start_flow()` method:
1. Wake screen
2. Navigate to vehicle dashboard via `_switch_vehicle()`
3. Dismiss system dialogs
4. Tap "Remote start" button → bottom sheet
5. Tap "Start" or "Stop"
6. Handle device pairing if needed
7. Enter SPIN if prompted
8. Take screencap for debugging

**Status:** Code deployed (v1.10.42). Not yet tested end-to-end because device
pairing must be completed first.

## XTEA Cipher Details

- 64-bit blocks, 128-bit key, 32 rounds
- Delta = 0x9E3779B9
- Key derivation from pairingKeySeed:
  1. pairingKeySeed (16 hex chars) → 64-bit integer
  2. Split to (hi, lo) = (upper 32 bits, lower 32 bits)
  3. temp_key = [hi, lo, ~hi & 0xFFFFFFFF, ~lo & 0xFFFFFFFF]
  4. XTEA-encrypt one block of zeros with temp_key
  5. final_key = [encrypted_hi, encrypted_lo, 0, 0]

## Encrypted Payload Construction

24 bytes (3 XTEA blocks):
```
ts[0] || ts[1] || hashedPinBytes(4) || ts[2] || captchaIndex(1) || captchaValue(1) || CRC8(1) || 0x00(1)
```

- Timestamps: [now_ms-4000, now_ms-2000, now_ms] / 1000 as uint32 BE (seconds)
- hashedPinBytes: First 4 bytes of SHA-512 hash of SPIN
- captchaIndex/captchaValue: From `/check` response, parsed as hex to bytes
- CRC-8: Polynomial 0x2F (SAE J1850), result inverted, over first 22 bytes + 0x00 pad
- Encoding: Hex-encoded uppercase (NOT base64)

## ECDSA Signing

- Signs: `pairingId.encode("utf-8") + encrypted_bytes`
- Key stored in Android Keystore, accessed via Frida `_sign_with_keystore()`
- rstSpinHash in payload = first 16 chars of SHA-512(SPIN) ONLY

## Device Pairing

Required before remote start can work. Per-device, one-time setup.

**Pairing data (Atlas):**
- pairingId: 856a16c4-3682-420f-98cf-8179fbc95d89
- pairingKeySeed: A7534E221EE63E7A
- mobileAppId: 9b6b9d-35ae-41e3-be67-1b58bf5d49ca

**UI Flow:**
1. Tap "Remote start" → bottom sheet
2. Tap "Start" → Device pairing dialog appears
3. Tap "Accept" → Pairing form (phone number + nickname)
4. Enter phone number → tap checkmark (submit)
5. [Unknown — not yet completed]

**Status:** Phone number was entered (905-929-4479) but form was never submitted.
Need to redo pairing after app restart.

## VW App UI Elements (720x1600 phone)

### Garage Screen
- "Log out" button: [28,90][137,129] (clickable)
- "Garage" title: [308,90][412,130]
- "Add" button: [636,90][692,129] (clickable)
- "2025 ID. Buzz 1st Edition": [63,229][622,269]
- "2024 Atlas": [63,615][622,655]

### Atlas Dashboard
- remoteStartButton: [35,822][685,934]
- "Remote start" text: [126,863][636,894]
- lockButton (Doors): [35,955][350,1067]
- honkFlashButton: [371,955][685,1067]
- Google Map: [35,1095][685,1319]
- "Updated at" text: [35,257][263,288] (clickable)

### Remote Start Bottom Sheet
- touch_outside: [0,0][720,1600]
- actionTitleTextView "Remote start": [35,1253][685,1335]
- firstCommandTextView "Stop": [35,1377][349,1481]
- secondCommandTextView "Start": [371,1377][685,1481]

## Known Issues

### "Media Storage keeps stopping" Dialog
- System crash dialog that appears randomly on Moto G Pure
- Blocks ALL touch events on the VW app
- Must be dismissed by tapping "Close app" button
- `_dismiss_system_dialogs()` helper handles this automatically
- Also handled in `_switch_vehicle()` dismiss loop

### su -c Required for All Input Commands
- `adb shell input tap` hangs as shell user on Moto G Pure
- Must use `adb shell su -c "input tap x y"` instead
- Fixed in all MQTT handlers and internal methods (v1.10.40)

### screencap Timeout When Screen Off
- `su -c screencap -p` hangs when display is off
- Fixed by calling `_wake_screen()` before screencap (v1.10.42)

## API Endpoints

- Base URL: `https://b-h-s.spr.ca00.p.con-veh.net`
- Challenge: GET `/ss/v1/user/{uid}/vehicle/{vid}/pairing/{pid}/challenge`
- Session: POST `/ss/v1/user/{uid}/vehicle/{vid}/pairing/{pid}/session`
- Check: POST `/ss/v1/user/{uid}/vehicle/{vid}/pairing/{pid}/climateControl/check`
- RST start: POST `/rst/v1/vehicle/{vid}`
- RST stop: DELETE `/rst/v1/vehicle/{vid}`
- RST history: GET `/rst/v1/vehicle/{vid}/history`
- Pairing: GET `/pair/v1/vehicle/{vid}`
- Eligibility: GET `/pair/v1/vehicle/{vid}/eligibity`

## MQTT Commands (Topic Prefix: vw/cmd/)

| Command | Payload | Description |
|---------|---------|-------------|
| remote_start | vehicle_id | API-driven RST (blocked by captcha) |
| remote_start_stop | vehicle_id | API-driven RST stop |
| ui_remote_start | vehicle_id | UI-driven RST via app buttons |
| ui_remote_start_stop | vehicle_id | UI-driven RST stop via app |
| get_pairing | vehicle_id | Fetch pairing data |
| screencap | (empty) | Take phone screenshot |
| ui_xml | (empty) | Dump UI hierarchy |
| ui_tap | element_text | Find and tap UI element |
| ui_find | search_text | Find UI elements |
| adb_tap | x,y | Tap coordinates |
| adb_shell | command | Run shell command |
| adb_swipe | x1,y1,x2,y2,ms | Swipe gesture |
| switch_vehicle | vehicle_id | Navigate to vehicle |
| wake_app | (empty) | Wake VW app |
| auto_login | (empty) | Full login flow |
| get_tokens | (empty) | Publish current tokens |
| clear_data | (empty) | Clear app data |

## Version History (RST-related)

- **v1.10.42** — Wake screen before screencap; prevent timeout
- **v1.10.41** — _dismiss_system_dialogs helper; _ui_remote_start_flow; MQTT ui_remote_start commands
- **v1.10.40** — Fix su -c in all MQTT tap handlers; exact text match preference
- **v1.10.x** — XTEA cipher, ATC session flow, encrypted payload construction

## Next Steps

1. Complete device pairing (submit form with phone number)
2. Test `ui_remote_start` end-to-end
3. Capture API traffic during successful UI-driven remote start
4. Determine if captcha can be extracted from traffic for API-only approach
5. Build HA automation for one-tap remote start
