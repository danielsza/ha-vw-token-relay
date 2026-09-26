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
