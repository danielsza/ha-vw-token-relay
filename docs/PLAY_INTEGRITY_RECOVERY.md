# Play Integrity Recovery — Moto G Pure (ellis) diagnosis & findings

This documents the Sept 2026 incident where the relay phone dropped to
`NO_INTEGRITY` and the full diagnostic chain, so it doesn't have to be
re-derived from scratch next time.

## Trigger
`pm clear com.google.android.gms` (run to force a GMS refresh) wiped GMS's
data **and its device registration**, then caused a boot loop. After recovery
+ a Magisk Direct-Install reinstall, Play Integrity returned `NO_INTEGRITY`
(fails even BASIC) and the VW app could no longer log in.

## Faults found and fixed (each verified)
1. **keystore2 `ErrorCode(-66)` / `-49`** — the device TEE cannot mint
   attestation keys. TrickyStore's default "leaf-hack" mode can't cover a
   broken TEE. Fixes tried:
   - Append `!` to `com.google.android.gms` in `/data/adb/tricky_store/target.txt`
     (forces TrickyStore *generate-key* mode). Removed the `-66` error.
   - **Better:** replaced TrickyStore with **TEESimulator-RS** (Enginex0),
     which runs a software KeyMint inside keystore2 and *forges* the
     attestation chain from the keybox (rooted under Google's root key),
     bypassing the dead TEE entirely. Installed over the `tricky_store`
     module slot (`libTEESimulator.so` loads into keystore2). This is the
     correct module for a broken-TEE device.
2. **Banned keybox** — the old keybox was the mass-banned AOSP "HelloWorld".
   Replaced with a fresh unrevoked one. Keybox path: `/data/adb/tricky_store/keybox.xml`.
   (TrickyStore-autofetch downloader was also broken — it called `curl`/`toybox
   wget`, which don't exist here; only `/data/adb/magisk/busybox wget` works.)
3. **Magisk DenyList disabled** during debugging — restored to enabled.
4. **Finsky `IntegrityException: User needs to (re)enter credentials`** — the
   `pm clear` wiped the Google account's auth tokens. Fixed by removing and
   re-adding the Google account (now automated in the relay: `vw/cmd/refresh_google`).
5. **Stale PIF fingerprint** — refreshed via autopif to a live Pixel Canary.
6. **DroidGuard crash-loop** — `DroidGuardService` was crashing (corrupt VM
   cache from the `pm clear`). Fixed by clearing `app_dg_cache`/`app_dgp` under
   `/data/data/com.google.android.gms/`.

## ROOT CAUSE (the wall)
GMS lost its **device registration** (no GSF `android_id`) and would not
re-register. Confirmed: `gservices.db` has the `android_id` key with **no
value**, and `content query ... gservices` returns nothing.

**Key discovery:** PIF's build-fingerprint spoofing prevents GMS check-in —
Google rejects a check-in whose fingerprint (Pixel) contradicts the rest of the
device signals (Moto G Pure). With **PIF disabled**, `am broadcast -a
android.server.checkin.CHECKIN` produced `Checkin Operation finished with
result: SUCCESS`. But re-enabling PIF (needed for the Pixel spoof that PI
requires) still did not yield a passing verdict — check-in wants the *real*
identity, PI wants the *spoofed* one, and this damaged GMS install can't hold
both. Verdict stayed `NO_INTEGRITY` through every combination.

## Conclusion / recommended fix
The GMS registration/DroidGuard state is damaged beyond incremental remote
repair. The reliable fix is a **factory reset** of this (disposable, dedicated)
phone, then rebuild the module stack cleanly. On a clean GMS the device
registers normally and PI passes.

### Recommended clean module stack (for the rebuild)
Per r/androidroot community guidance for broken-TEE devices:
- **ReZygisk** (Zygisk provider; keep Magisk built-in zygisk OFF)
- **TEESimulator-RS** (Enginex0) — software TEE / keystore attestation
- **PlayIntegrityFix-Inject** or Play Integrity Fork — surgical DroidGuard-only
  fingerprint spoof (less likely to break check-in than a broad PIF)
- Optional: **Specter** (dpejoh) to coordinate keybox/target/security-patch,
  or **AlwaysStrong** (evoker0) = one-flash TEESimulator-RS + PlayIntegrityFork
- A fresh, unrevoked hardware keybox at `/data/adb/tricky_store/keybox.xml`

### Order-of-operations note (critical)
Register GMS FIRST (real identity, PIF/spoof OFF) so it gets a valid
`android_id` and certifies, THEN enable the spoofing modules for PI. Never
`pm clear com.google.android.gms` on a spoofed device — it forces a re-checkin
that the spoof will fail.

## Relay add-on changes made during this incident (v1.21.x)
- `vw/cmd/maintenance` on/off — pauses the keepalive/auto-login loop so long UI
  tasks can drive Settings without the VW app stealing focus.
- `vw/cmd/refresh_google` — headless Google account remove+re-add using the
  stored `google_email`/`google_password`; Android-12 nav fixed (base64-wrapped
  `AccountDashboardActivity` launch; force-stops the VW app during the flow).
- 2FA support: detects a Google 2-step challenge, publishes `vw/google_refresh`
  `{status: 2fa_required}` + a critical `vw/notify`, waits for a code from
  `vw/cmd/twofa_code`; the web remote UI has a 2FA code input that POSTs `/twofa`.

---

## Rebuild after factory reset (Sept 26 2026)

The factory reset + clean rebuild worked and confirmed the root-cause theory:
on a clean GMS the device **re-registers normally**. Full sequence below —
this is the current known-good rebuild procedure.

### 0. Re-root (Magisk 30.7)
- Bootloader already unlocked. Magisk app "Direct Install" patched the live
  boot; reboot brought back `su` at `/debug_ramdisk/su`.
- **Gotcha:** after a reset, ADB `su` requests are auto-**rejected**
  (`Magisk: su: request rejected (2000)`) even though the app has root. The
  Settings-screen "Superuser access = Apps and ADB" / "Automatic response"
  writes did **not** reach the daemon. The fix that worked: open Magisk →
  **Superuser tab** → toggle the **`[SharedUID] Shell` (com.android.shell)**
  switch ON. That writes a persistent policy (`policies: uid=2000 policy=2
  until=0`). Hardened with `magisk --sqlite "REPLACE INTO settings ... root_access=3"`.

### 1. Register GMS FIRST (no spoof) — THE root-cause fix
- With **no** spoofing modules loaded: `am broadcast -a
  android.server.checkin.CHECKIN` → `Checkin ... SUCCESS`.
- Verified `android_id` is now **populated** (was empty before):
  `gservices.db` → `android_id = 4228488890168138410`, `device_country = ca`,
  1392 rows. This is the registration whose absence broke everything.
- `sqlite3` is not on the device; pull `gservices.db` and read it on a host.

### 2. Module stack (all 32-bit armeabi-v7a, current versions)
- **Magisk built-in Zygisk** (`magisk --sqlite "... zygisk=1"`) — did NOT need
  ReZygisk; built-in works here. Enforce DenyList = 1; denylist has
  `com.google.android.gms` (+ `.unstable`) and `com.android.vending`.
- **TrickyStore 1.4.1** (5ec1cff) — `libtricky_store.so` confirmed mapped into
  `keystore2`. NOTE: post-reset the TEE actually works
  (`TlcTeeKeyMaster: TEE_AttestKey exiting with 0`, `tee_status=teeBroken=false`,
  no more keystore2 `-66/-49`), so TEESimulator-RS was NOT needed this time —
  plain TrickyStore generate-mode (`!` in target.txt) is enough.
- **PlayIntegrityFork v18** (osm0sis) — injects into `gms.unstable`
  (`PIF/Native` in logcat). Fingerprint via `autopif4.sh -m` writes
  `custom.pif.prop`.
- **TrickyStore-autofetch v1.3.0** (R05P0) — revocation-aware keybox +
  fingerprint auto-manager, WebUI, runs on boot + every 6h. Config at
  `/data/adb/trickystore_autofetch/config.conf`. Set `RENEW_PIF=0` while there
  is no Google account (see below).

### 3. KEYBOX EXPIRED — the newly-discovered wall
- **The old `ddex/lonemods` keybox leaf expired `Sep 26 16:57 2026` — i.e. it
  died on the exact day of this incident.** An expired leaf in the chain makes
  Play Integrity go UNEVALUATED/NO for DEVICE regardless of everything else.
  This would have broken DEVICE integrity even without the GMS damage.
- Fix: the ddex source repo (`dare-devil-ex/keyboxxBot`, raw `keybox.xml`) has
  **rotated to a fresh keybox** — leaf valid to **Nov 30 2028**, and all 5
  serials are **NOT** in Google's CRL (`android.googleapis.com/attestation/status`,
  1755 revoked entries). Installed at `/data/adb/tricky_store/keybox.xml`.
  TrickyStore-autofetch (source `ddex`) will keep this refreshed automatically.
- **Always re-check keybox leaf expiry + CRL when PI drops.** A keybox can be
  unrevoked yet expired.

### 4. Current verdict + the DEVICE gap (still open)
- **`MEETS_BASIC_INTEGRITY`** with valid keybox + configless PIF (real Moto
  fingerprint). Confirmed reproducible.
- Applying the Pixel 9a Canary fingerprint (`autopif`, `tegu`/`ZP11.260821.010`)
  drops it to **NO_INTEGRITY** — the Canary build appears **not recognized**
  without a beta-enrolled Google account, so it fails even basic.
- **No Google account is signed in yet.** The recovery note (README) says a
  missing/stale account makes Finsky fall back to basic-only. Strong hypothesis:
  **DEVICE needs (a) a signed-in (beta-enrolled) Google account + (b) the Pixel
  Canary fingerprint + (c) the valid keybox together.** With no account, keep
  PIF configless (BASIC) — that's why `RENEW_PIF=0` for now.
- **Next step to reach DEVICE:** sign the Google account back in
  (`danielsza@gmail.com`) — either via the relay's `vw/cmd/refresh_google` once
  the relay is reconnected, or manually — then re-enable the Canary fingerprint
  (`RENEW_PIF=1` / run autopif) and reboot; re-test SPIC.

### 5. Connectivity for the relay
- Network ADB enabled: `adb tcpip 5555`, phone IP `192.168.0.77:5555`. The relay
  host must re-authorize its ADB key (phone was wiped) before the relay resumes.
- Still to restore: sideload myVW (`com.vw.carnet.releaseca`) + 32-bit arm Frida
  server, re-pair ADB from the relay add-on, sign in Google, then verify VW login.
