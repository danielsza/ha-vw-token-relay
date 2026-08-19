#!/usr/bin/env python3
"""
VW app auto-login via ADB UI automation.

Called by vw_token_relay.py when the app's session expires (~30 days)
and needs a fresh login. Uses ADB input commands to tap through the
login flow without human intervention.

Usage:
    python3 vw_auto_login.py --email <email> --password <pass> --spin <spin>
"""

import argparse
import logging
import subprocess
import time
import sys

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("vw-auto-login")

VW_PACKAGE = "com.vw.carnet.releaseca"
VW_ACTIVITY = "com.vw.myVW.activities.RoutingActivity"


def adb(*args, timeout=10):
    """Run an ADB command and return stdout."""
    cmd = ["adb"] + list(args)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception as e:
        log.error("ADB error: %s", e)
        return ""


def tap(x, y, delay=0.5):
    """Tap a screen coordinate."""
    adb("shell", f"input tap {x} {y}")
    time.sleep(delay)


def type_text(text):
    """Type text via ADB input (escapes spaces)."""
    escaped = text.replace(" ", "%s").replace("&", "\\&").replace("|", "\\|")
    adb("shell", f"input text '{escaped}'")
    time.sleep(0.3)


def wake_and_unlock():
    """Wake screen and dismiss lock screen."""
    screen = adb("shell", "dumpsys power | grep 'Display Power'")
    if "OFF" in screen:
        adb("shell", "input keyevent KEYCODE_WAKEUP")
        time.sleep(1)
        adb("shell", "input swipe 540 1800 540 800 300")
        time.sleep(1)


def get_current_activity():
    """Get the current foreground activity."""
    out = adb("shell", "dumpsys activity activities | grep mResumedActivity")
    return out


def wait_for_activity(fragment, timeout=30):
    """Wait until a specific activity/fragment is in the foreground."""
    for _ in range(timeout):
        act = get_current_activity()
        if fragment in act:
            return True
        time.sleep(1)
    return False


def clear_and_relaunch():
    """Force-stop and relaunch the VW app."""
    log.info("Force-stopping VW app...")
    adb("shell", f"am force-stop {VW_PACKAGE}")
    time.sleep(2)
    log.info("Launching VW app...")
    adb("shell", f"am start -n {VW_PACKAGE}/{VW_ACTIVITY}")
    time.sleep(5)


def login(email, password, spin):
    """
    Automate the VW app login flow via ADB taps and text input.

    The VW app login flow (approximate coordinates for Moto G Pure 720x1600):
    1. App launches → splash screen → login screen
    2. "Log in" or "Sign in" button
    3. Email field → type email
    4. Password field → type password
    5. Submit button
    6. Possible 2FA or terms acceptance

    NOTE: These coordinates are approximate and may need adjustment.
    The Moto G Pure has a 720x1600 screen.
    """
    wake_and_unlock()
    clear_and_relaunch()

    # Wait for app to fully load
    log.info("Waiting for app to load...")
    time.sleep(8)

    # Check if we're on a login screen by looking for WebView/login activity
    activity = get_current_activity()
    log.info("Current activity: %s", activity)

    # The VW app uses a WebView for login (identity.na.vwgroup.io)
    # We need to interact with the WebView's form fields

    # Step 1: Look for and tap "Log in" / "Sign in" button if present
    # Try tapping center-bottom area where login buttons typically are
    log.info("Looking for login button...")
    tap(360, 1300, delay=2)

    # Step 2: If we hit a WebView login form, find the email field
    # The email field is typically near the top-center of the form
    log.info("Entering email...")
    # Tap email field area
    tap(360, 600, delay=1)
    # Clear any existing text
    adb("shell", "input keyevent KEYCODE_CTRL_LEFT+KEYCODE_A")
    time.sleep(0.2)
    adb("shell", "input keyevent KEYCODE_DEL")
    time.sleep(0.2)
    # Type email
    type_text(email)

    # Step 3: Tap "Next" or move to password field
    log.info("Moving to password field...")
    tap(360, 800, delay=1)  # Tap password field
    # Clear and type password
    adb("shell", "input keyevent KEYCODE_CTRL_LEFT+KEYCODE_A")
    time.sleep(0.2)
    adb("shell", "input keyevent KEYCODE_DEL")
    time.sleep(0.2)
    type_text(password)

    # Step 4: Submit
    log.info("Submitting login...")
    tap(360, 1100, delay=3)  # Submit button

    # Step 5: Wait for login to complete
    log.info("Waiting for login to complete...")
    time.sleep(10)

    # Check if we're past the login screen
    activity = get_current_activity()
    log.info("Post-login activity: %s", activity)

    # If there's a "Continue" or terms dialog, tap through it
    tap(360, 1200, delay=2)
    tap(360, 1200, delay=2)

    # Wait for the app to settle and make API calls
    time.sleep(10)

    activity = get_current_activity()
    log.info("Final activity: %s", activity)

    if VW_PACKAGE in activity:
        log.info("Login appears successful — app is running")
        return True
    else:
        log.warning("Login status uncertain — check app manually")
        return False


def main():
    p = argparse.ArgumentParser(description="VW app auto-login via ADB")
    p.add_argument("--email", required=True, help="VW account email")
    p.add_argument("--password", required=True, help="VW account password")
    p.add_argument("--spin", required=True, help="VW S-PIN")
    args = p.parse_args()

    log.info("Starting VW auto-login for %s", args.email)
    success = login(args.email, args.password, args.spin)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
