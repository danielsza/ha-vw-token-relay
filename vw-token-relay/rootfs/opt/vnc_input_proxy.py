#!/usr/bin/env python3
"""
VNC Input Proxy — intercepts VNC client input events and injects them via ADB.

droidVNC-NG's InputService (AccessibilityService) fails to bind on some devices,
causing all VNC client input (mouse/keyboard) to be silently dropped. This proxy
sits between the VNC client and droidVNC-NG's VNC server:

  VNC Client → [Proxy :5900] → droidVNC-NG :15900 (via ADB forward)
                  ↓ (input events)
                adb shell input tap/swipe/text/keyevent

Screen data flows through unchanged. Input events are intercepted and translated
to ADB input injection commands, which work with root/ADB without needing
AccessibilityService.
"""

import socket
import struct
import subprocess
import threading
import time
import sys
import os
import signal

LISTEN_PORT = int(os.environ.get('VNC_PROXY_PORT', '5900'))
VNC_HOST = '127.0.0.1'
VNC_PORT = int(os.environ.get('VNC_BACKEND_PORT', '15900'))

# Throttle: minimum ms between ADB input commands
INPUT_THROTTLE_MS = 50
_last_input_time = 0
_input_lock = threading.Lock()


def adb_input(cmd):
    """Execute an ADB input command (non-blocking)."""
    global _last_input_time
    now = time.time() * 1000
    with _input_lock:
        elapsed = now - _last_input_time
        if elapsed < INPUT_THROTTLE_MS:
            return  # throttle
        _last_input_time = now
    try:
        subprocess.Popen(
            ['adb', 'shell', cmd],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except Exception as e:
        print(f"VNC proxy: adb_input error: {e}", file=sys.stderr)


def adb_input_blocking(cmd):
    """Execute an ADB input command (blocking, for text input)."""
    try:
        subprocess.run(
            ['adb', 'shell', cmd],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5
        )
    except Exception as e:
        print(f"VNC proxy: adb_input error: {e}", file=sys.stderr)


# X11 keysym → Android KEYCODE mapping
KEYSYM_TO_KEYCODE = {
    0xff0d: 66,    # Return → ENTER
    0xff1b: 111,   # Escape → ESCAPE (Back)
    0xff08: 67,    # BackSpace → DEL
    0xffff: 112,   # Delete → FORWARD_DEL
    0xff09: 61,    # Tab → TAB
    0xff50: 122,   # Home → HOME (move to start)
    0xff57: 123,   # End → MOVE_END
    0xff51: 21,    # Left → DPAD_LEFT
    0xff52: 19,    # Up → DPAD_UP
    0xff53: 22,    # Right → DPAD_RIGHT
    0xff54: 20,    # Down → DPAD_DOWN
    0xff55: 92,    # Page_Up
    0xff56: 93,    # Page_Down
    0xffe1: -1,    # Shift_L (modifier, ignore)
    0xffe2: -1,    # Shift_R
    0xffe3: -1,    # Control_L
    0xffe4: -1,    # Control_R
    0xffe9: -1,    # Alt_L
    0xffea: -1,    # Alt_R
    0xffeb: -1,    # Super_L
    0x0020: 62,    # Space → SPACE
    0xff63: -1,    # Insert (ignore)
    0xff14: -1,    # Scroll_Lock (ignore)
    0xffbe: -1,    # F1 (ignore)
    0xffbf: -1,    # F2
    0xffc0: -1,    # F3
    0xffc1: -1,    # F4
    0xffc2: -1,    # F5
    0xffc3: -1,    # F6
    0xffc4: -1,    # F7
    0xffc5: -1,    # F8
    0xffc6: -1,    # F9
    0xffc7: -1,    # F10
    0xffc8: -1,    # F11
    0xffc9: -1,    # F12
}


def handle_key(down_flag, keysym):
    """Handle VNC key event → ADB keyevent or text input."""
    if not down_flag:
        return  # Only act on key press, not release

    # Check mapped special keys
    if keysym in KEYSYM_TO_KEYCODE:
        keycode = KEYSYM_TO_KEYCODE[keysym]
        if keycode >= 0:
            adb_input(f'input keyevent {keycode}')
        return

    # Printable ASCII → input text
    if 0x20 <= keysym <= 0x7e:
        char = chr(keysym)
        # Escape shell-special characters
        if char in "'\"\\$`!":
            adb_input_blocking(f"input text '{char}'")
        else:
            adb_input(f'input text "{char}"')
        return

    # Latin-1 range
    if 0xa0 <= keysym <= 0xff:
        char = chr(keysym)
        adb_input_blocking(f"input text '{char}'")
        return


class PointerState:
    """Track VNC pointer state for click/drag/scroll detection."""

    def __init__(self):
        self.button_mask = 0
        self.x = 0
        self.y = 0
        self.press_x = 0
        self.press_y = 0
        self.press_time = 0
        self.dragging = False

    def update(self, button_mask, x, y):
        prev_mask = self.button_mask
        self.button_mask = button_mask
        self.x = x
        self.y = y

        # Left button transitions
        left_was = prev_mask & 1
        left_now = button_mask & 1

        if left_now and not left_was:
            # Button pressed
            self.press_x = x
            self.press_y = y
            self.press_time = time.time()
            self.dragging = False

        elif not left_now and left_was:
            # Button released
            dx = abs(x - self.press_x)
            dy = abs(y - self.press_y)
            duration = time.time() - self.press_time

            if dx > 10 or dy > 10:
                # Drag/swipe
                dur_ms = max(100, int(duration * 1000))
                adb_input(f'input swipe {self.press_x} {self.press_y} {x} {y} {dur_ms}')
            elif duration > 0.5:
                # Long press
                adb_input(f'input swipe {x} {y} {x} {y} {int(duration * 1000)}')
            else:
                # Tap
                adb_input(f'input tap {x} {y}')

            self.dragging = False

        # Scroll (buttons 4=up, 5=down in VNC)
        if (button_mask & 8) and not (prev_mask & 8):
            adb_input(f'input swipe {x} {y} {x} {max(0, y - 200)} 100')  # scroll up
        if (button_mask & 16) and not (prev_mask & 16):
            adb_input(f'input swipe {x} {y} {x} {y + 200} 100')  # scroll down


def recv_exact(sock, n):
    """Receive exactly n bytes from socket."""
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    return data


def forward_thread(src, dst, name="fwd"):
    """Forward all data from src to dst until either closes."""
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except (ConnectionError, OSError):
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle_client(client_sock, addr):
    """Handle a VNC client connection through the proxy."""
    print(f"VNC proxy: Client connected from {addr}")

    vnc_sock = None
    try:
        # Connect to real VNC server
        vnc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        vnc_sock.settimeout(10)
        vnc_sock.connect((VNC_HOST, VNC_PORT))
        vnc_sock.settimeout(None)

        # === RFB Handshake ===

        # 1. Protocol version (12 bytes each way)
        server_version = recv_exact(vnc_sock, 12)
        print(f"VNC proxy: Server version: {server_version.strip()}")
        client_sock.sendall(server_version)

        client_version = recv_exact(client_sock, 12)
        print(f"VNC proxy: Client version: {client_version.strip()}")
        vnc_sock.sendall(client_version)

        # 2. Security handshake
        # RFB 3.8: server sends count + type list
        num_types_byte = recv_exact(vnc_sock, 1)
        num_types = struct.unpack('B', num_types_byte)[0]

        if num_types == 0:
            # Connection failed — read reason and forward
            reason_len = struct.unpack('>I', recv_exact(vnc_sock, 4))[0]
            reason = recv_exact(vnc_sock, reason_len)
            client_sock.sendall(num_types_byte + struct.pack('>I', reason_len) + reason)
            print(f"VNC proxy: Server rejected: {reason}")
            return

        sec_types = recv_exact(vnc_sock, num_types)
        client_sock.sendall(num_types_byte + sec_types)
        print(f"VNC proxy: Security types: {list(sec_types)}")

        # Client selects security type
        selected = recv_exact(client_sock, 1)
        vnc_sock.sendall(selected)
        selected_type = struct.unpack('B', selected)[0]
        print(f"VNC proxy: Client selected security type {selected_type}")

        if selected_type == 2:
            # VNC Authentication: forward 16-byte challenge/response
            challenge = recv_exact(vnc_sock, 16)
            client_sock.sendall(challenge)
            response = recv_exact(client_sock, 16)
            vnc_sock.sendall(response)

        # Security result (4 bytes)
        result = recv_exact(vnc_sock, 4)
        client_sock.sendall(result)
        result_code = struct.unpack('>I', result)[0]
        if result_code != 0:
            print(f"VNC proxy: Authentication failed (code {result_code})")
            # Try to forward error message if present
            try:
                vnc_sock.settimeout(2)
                err_len_data = vnc_sock.recv(4)
                if len(err_len_data) == 4:
                    err_len = struct.unpack('>I', err_len_data)[0]
                    err_msg = recv_exact(vnc_sock, err_len)
                    client_sock.sendall(err_len_data + err_msg)
            except:
                pass
            return

        # 3. ClientInit (1 byte shared flag)
        client_init = recv_exact(client_sock, 1)
        vnc_sock.sendall(client_init)

        # 4. ServerInit (2+2+16+4+name)
        server_init = recv_exact(vnc_sock, 24)
        fb_width = struct.unpack('>H', server_init[0:2])[0]
        fb_height = struct.unpack('>H', server_init[2:4])[0]
        name_len = struct.unpack('>I', server_init[20:24])[0]
        server_name = recv_exact(vnc_sock, name_len)
        client_sock.sendall(server_init + server_name)
        print(f"VNC proxy: Framebuffer {fb_width}x{fb_height}, name={server_name}")

        # === Main loop ===
        # Forward server→client in a background thread
        srv_thread = threading.Thread(
            target=forward_thread,
            args=(vnc_sock, client_sock, "server→client"),
            daemon=True
        )
        srv_thread.start()

        # Handle client→server messages (intercept input)
        pointer = PointerState()

        while True:
            msg_type_data = recv_exact(client_sock, 1)
            msg_type = struct.unpack('B', msg_type_data)[0]

            if msg_type == 0:
                # SetPixelFormat: 3 padding + 16 pixel format = 19 bytes
                data = recv_exact(client_sock, 19)
                vnc_sock.sendall(msg_type_data + data)

            elif msg_type == 2:
                # SetEncodings: 1 padding + 2 count + 4*count encodings
                pad_and_count = recv_exact(client_sock, 3)
                n_enc = struct.unpack('>H', pad_and_count[1:3])[0]
                encodings = recv_exact(client_sock, n_enc * 4)
                vnc_sock.sendall(msg_type_data + pad_and_count + encodings)

            elif msg_type == 3:
                # FramebufferUpdateRequest: 9 bytes
                data = recv_exact(client_sock, 9)
                vnc_sock.sendall(msg_type_data + data)

            elif msg_type == 4:
                # KeyEvent: 1 down + 2 padding + 4 key = 7 bytes
                data = recv_exact(client_sock, 7)
                down_flag = struct.unpack('B', data[0:1])[0]
                keysym = struct.unpack('>I', data[3:7])[0]
                handle_key(down_flag, keysym)
                # Do NOT forward to server (InputService is broken)

            elif msg_type == 5:
                # PointerEvent: 1 button_mask + 2 x + 2 y = 5 bytes
                data = recv_exact(client_sock, 5)
                button_mask = struct.unpack('B', data[0:1])[0]
                x = struct.unpack('>H', data[1:3])[0]
                y = struct.unpack('>H', data[3:5])[0]
                pointer.update(button_mask, x, y)
                # Do NOT forward to server (InputService is broken)

            elif msg_type == 6:
                # ClientCutText: 3 padding + 4 length + text
                pad = recv_exact(client_sock, 3)
                length_data = recv_exact(client_sock, 4)
                length = struct.unpack('>I', length_data)[0]
                text = recv_exact(client_sock, length)
                vnc_sock.sendall(msg_type_data + pad + length_data + text)

            else:
                # Unknown — forward the type byte and hope for the best
                vnc_sock.sendall(msg_type_data)

    except ConnectionError as e:
        print(f"VNC proxy: Connection closed: {e}")
    except Exception as e:
        print(f"VNC proxy: Error: {e}", file=sys.stderr)
    finally:
        if vnc_sock:
            try:
                vnc_sock.close()
            except:
                pass
        try:
            client_sock.close()
        except:
            pass
        print(f"VNC proxy: Client {addr} disconnected")


def main():
    # Ignore SIGPIPE
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', LISTEN_PORT))
    server.listen(2)
    print(f"VNC proxy: Listening on :{LISTEN_PORT} → {VNC_HOST}:{VNC_PORT}")
    print(f"VNC proxy: Input events will be injected via ADB")

    while True:
        try:
            client_sock, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(client_sock, addr), daemon=True)
            t.start()
        except Exception as e:
            print(f"VNC proxy: Accept error: {e}", file=sys.stderr)
            time.sleep(1)


if __name__ == '__main__':
    main()
