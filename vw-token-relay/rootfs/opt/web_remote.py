#!/usr/bin/env python3
"""
Web-based phone remote viewer for VW Token Relay addon.

Replaces the broken droidVNC-NG setup with a simple, reliable approach:
  - Screen: ADB screencap (works with root, no permissions needed)
  - Input: ADB input tap/swipe/keyevent (works with root)
  - Served on the addon's ingress port (8099)

No MediaProjection consent, no AccessibilityService, no VNC protocol.
Just ADB — which always works on a rooted phone with USB.
"""

import http.server
import json
import subprocess
import threading
import time
import os
import sys
import io
import socketserver

PORT = int(os.environ.get('WEB_REMOTE_PORT', '8099'))
SCREEN_WIDTH = 720
SCREEN_HEIGHT = 1600

# Rate-limit screenshots to avoid hammering ADB
_screenshot_lock = threading.Lock()
_screenshot_cache = None
_screenshot_time = 0
SCREENSHOT_CACHE_MS = 800  # min ms between screencaps

def take_screenshot():
    """Take a screenshot via ADB and return PNG bytes."""
    global _screenshot_cache, _screenshot_time
    now = time.time() * 1000
    with _screenshot_lock:
        if _screenshot_cache and (now - _screenshot_time) < SCREENSHOT_CACHE_MS:
            return _screenshot_cache
    try:
        r = subprocess.run(
            ['adb', 'exec-out', 'screencap', '-p'],
            capture_output=True, timeout=10)
        if r.returncode == 0 and len(r.stdout) > 100:
            with _screenshot_lock:
                _screenshot_cache = r.stdout
                _screenshot_time = time.time() * 1000
            return r.stdout
    except Exception as e:
        print(f"WebRemote: screenshot error: {e}", file=sys.stderr)
    return _screenshot_cache or b''


def adb_input(cmd):
    """Run an ADB input command."""
    try:
        subprocess.run(
            ['adb', 'shell', cmd],
            capture_output=True, timeout=5)
    except Exception as e:
        print(f"WebRemote: input error: {e}", file=sys.stderr)


HTML_PAGE = r'''<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Phone Remote</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    background: #1a1a2e; color: #eee; font-family: system-ui, sans-serif;
    display: flex; flex-direction: column; align-items: center;
    min-height: 100vh; padding: 8px;
}
h1 { font-size: 14px; color: #888; margin: 4px 0; }
.container {
    display: flex; gap: 12px; align-items: flex-start;
    flex-wrap: wrap; justify-content: center;
}
.phone-frame {
    position: relative; border: 2px solid #333; border-radius: 12px;
    overflow: hidden; background: #000; cursor: crosshair;
    touch-action: none;
}
.phone-frame img {
    display: block; max-height: 75vh; width: auto;
    pointer-events: none; user-select: none;
    -webkit-user-drag: none;
}
.controls {
    display: flex; flex-direction: column; gap: 6px;
}
.controls button {
    background: #2a2a4a; border: 1px solid #444; color: #ddd;
    padding: 10px 16px; border-radius: 6px; cursor: pointer;
    font-size: 13px; min-width: 80px; text-align: center;
    transition: background 0.15s;
}
.controls button:hover { background: #3a3a6a; }
.controls button:active { background: #4a4aaa; }
.controls .sep { height: 8px; }
.status {
    font-size: 11px; color: #666; margin-top: 4px;
    text-align: center;
}
.status.ok { color: #4a4; }
.status.err { color: #a44; }
.touch-dot {
    position: absolute; width: 20px; height: 20px;
    border-radius: 50%; background: rgba(255,100,100,0.6);
    border: 2px solid rgba(255,255,255,0.5);
    transform: translate(-50%, -50%);
    pointer-events: none; transition: opacity 0.3s;
}
.refresh-controls {
    display: flex; align-items: center; gap: 8px; margin: 4px 0;
}
.refresh-controls label { font-size: 12px; color: #888; }
.refresh-controls input[type=range] { width: 80px; }
.refresh-controls span { font-size: 11px; color: #aaa; min-width: 30px; }
</style>
</head>
<body>
<h1>VW Token Relay — Phone Remote</h1>
<div class="refresh-controls">
    <label>Refresh:</label>
    <input type="range" id="refreshRate" min="500" max="5000" step="250" value="1500">
    <span id="refreshLabel">1.5s</span>
    <button onclick="refreshNow()" style="background:#2a2a4a;border:1px solid #444;color:#ddd;padding:3px 10px;border-radius:4px;cursor:pointer;font-size:11px;">Now</button>
    <label style="margin-left:8px"><input type="checkbox" id="autoPause" checked> Pause when hidden</label>
</div>
<div class="container">
    <div class="phone-frame" id="phoneFrame">
        <img id="screen" src="/screenshot" alt="Phone screen">
    </div>
    <div class="controls">
        <button onclick="sendKey(3)">&#8962; Home</button>
        <button onclick="sendKey(4)">&#8592; Back</button>
        <button onclick="sendKey(187)">&#9744; Recent</button>
        <div class="sep"></div>
        <button onclick="sendKey(26)">&#9211; Power</button>
        <button onclick="sendKey(24)">Vol +</button>
        <button onclick="sendKey(25)">Vol -</button>
        <div class="sep"></div>
        <button onclick="wake()">Wake Screen</button>
        <button onclick="sendKey(82)">Menu</button>
        <div class="sep"></div>
        <button onclick="sendSwipe(360,1400,360,600,300)">Swipe Up</button>
        <button onclick="sendSwipe(360,600,360,1400,300)">Swipe Down</button>
    </div>
</div>
<div class="status" id="status">Connecting...</div>

<script>
const img = document.getElementById('screen');
const frame = document.getElementById('phoneFrame');
const statusEl = document.getElementById('status');
const refreshSlider = document.getElementById('refreshRate');
const refreshLabel = document.getElementById('refreshLabel');
const autoPause = document.getElementById('autoPause');
let refreshInterval = 1500;
let refreshTimer = null;
let phoneW = 720, phoneH = 1600;
let pointerDown = false, startX = 0, startY = 0, startTime = 0;

// Coordinate mapping: image pixel → phone pixel
function imgToPhone(clientX, clientY) {
    const rect = img.getBoundingClientRect();
    const imgX = clientX - rect.left;
    const imgY = clientY - rect.top;
    const scaleX = phoneW / rect.width;
    const scaleY = phoneH / rect.height;
    return [Math.round(imgX * scaleX), Math.round(imgY * scaleY)];
}

function showTap(clientX, clientY) {
    const rect = frame.getBoundingClientRect();
    const dot = document.createElement('div');
    dot.className = 'touch-dot';
    dot.style.left = (clientX - rect.left) + 'px';
    dot.style.top = (clientY - rect.top) + 'px';
    frame.appendChild(dot);
    setTimeout(() => { dot.style.opacity = '0'; }, 200);
    setTimeout(() => { dot.remove(); }, 500);
}

// Pointer events (work for both mouse and touch)
frame.addEventListener('pointerdown', e => {
    e.preventDefault();
    pointerDown = true;
    startX = e.clientX; startY = e.clientY;
    startTime = Date.now();
    frame.setPointerCapture(e.pointerId);
});

frame.addEventListener('pointerup', e => {
    if (!pointerDown) return;
    pointerDown = false;
    const dx = Math.abs(e.clientX - startX);
    const dy = Math.abs(e.clientY - startY);
    const duration = Date.now() - startTime;

    if (dx > 15 || dy > 15) {
        // Swipe
        const [sx, sy] = imgToPhone(startX, startY);
        const [ex, ey] = imgToPhone(e.clientX, e.clientY);
        const dur = Math.max(100, duration);
        sendSwipe(sx, sy, ex, ey, dur);
        showTap(startX, startY);
        showTap(e.clientX, e.clientY);
    } else if (duration > 600) {
        // Long press
        const [px, py] = imgToPhone(e.clientX, e.clientY);
        sendLongPress(px, py, duration);
        showTap(e.clientX, e.clientY);
    } else {
        // Tap
        const [px, py] = imgToPhone(e.clientX, e.clientY);
        sendTap(px, py);
        showTap(e.clientX, e.clientY);
    }
});

frame.addEventListener('pointercancel', () => { pointerDown = false; });

// Prevent context menu on long press
frame.addEventListener('contextmenu', e => e.preventDefault());

function setStatus(msg, ok) {
    statusEl.textContent = msg;
    statusEl.className = 'status ' + (ok ? 'ok' : 'err');
}

async function sendTap(x, y) {
    setStatus(`Tap ${x},${y}...`, true);
    try {
        await fetch('/input', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({action: 'tap', x, y})
        });
        setTimeout(refreshNow, 300);
    } catch(e) { setStatus('Tap failed: ' + e, false); }
}

async function sendSwipe(x1, y1, x2, y2, dur) {
    setStatus(`Swipe ${x1},${y1} → ${x2},${y2}`, true);
    try {
        await fetch('/input', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({action: 'swipe', x1, y1, x2, y2, duration: dur})
        });
        setTimeout(refreshNow, 400);
    } catch(e) { setStatus('Swipe failed: ' + e, false); }
}

async function sendLongPress(x, y, dur) {
    setStatus(`Long press ${x},${y} (${dur}ms)`, true);
    try {
        await fetch('/input', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({action: 'longpress', x, y, duration: dur})
        });
        setTimeout(refreshNow, 400);
    } catch(e) { setStatus('Long press failed: ' + e, false); }
}

async function sendKey(keycode) {
    setStatus(`Key ${keycode}...`, true);
    try {
        await fetch('/input', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({action: 'key', keycode})
        });
        setTimeout(refreshNow, 300);
    } catch(e) { setStatus('Key failed: ' + e, false); }
}

async function wake() {
    setStatus('Waking screen...', true);
    try {
        await fetch('/input', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({action: 'wake'})
        });
        setTimeout(refreshNow, 1000);
    } catch(e) { setStatus('Wake failed: ' + e, false); }
}

function refreshNow() {
    const ts = Date.now();
    const newImg = new Image();
    newImg.onload = () => {
        img.src = newImg.src;
        setStatus('Live — ' + new Date().toLocaleTimeString(), true);
    };
    newImg.onerror = () => {
        setStatus('Screenshot failed', false);
    };
    newImg.src = '/screenshot?t=' + ts;
}

function startRefresh() {
    stopRefresh();
    refreshTimer = setInterval(() => {
        if (autoPause.checked && document.hidden) return;
        refreshNow();
    }, refreshInterval);
    refreshNow();
}

function stopRefresh() {
    if (refreshTimer) { clearInterval(refreshTimer); refreshTimer = null; }
}

refreshSlider.addEventListener('input', () => {
    refreshInterval = parseInt(refreshSlider.value);
    refreshLabel.textContent = (refreshInterval / 1000).toFixed(1) + 's';
    startRefresh();
});

document.addEventListener('visibilitychange', () => {
    if (!document.hidden && autoPause.checked) refreshNow();
});

// Start
startRefresh();
</script>
</body>
</html>'''


class RemoteHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler for the web remote viewer."""

    def log_message(self, format, *args):
        # Suppress noisy access logs for screenshot polling
        if '/screenshot' not in str(args[0]):
            print(f"WebRemote: {args[0]}", file=sys.stderr)

    def _send_json(self, data, code=200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html):
        body = html.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split('?')[0]

        if path == '/' or path == '/index.html':
            self._send_html(HTML_PAGE)

        elif path == '/screenshot':
            png = take_screenshot()
            if png:
                self.send_response(200)
                self.send_header('Content-Type', 'image/png')
                self.send_header('Content-Length', str(len(png)))
                self.send_header('Cache-Control', 'no-cache, no-store')
                self.end_headers()
                self.wfile.write(png)
            else:
                self._send_json({'error': 'no screenshot available'}, 503)

        elif path == '/status':
            # Quick health check
            try:
                r = subprocess.run(
                    ['adb', 'devices'], capture_output=True, text=True, timeout=5)
                connected = 'device' in r.stdout
            except:
                connected = False
            self._send_json({'connected': connected})

        else:
            # Fall through to serve static files from /share/ (legacy)
            try:
                file_path = os.path.join('/share', path.lstrip('/'))
                if os.path.isfile(file_path):
                    with open(file_path, 'rb') as f:
                        data = f.read()
                    self.send_response(200)
                    ct = 'application/octet-stream'
                    if file_path.endswith('.html'): ct = 'text/html'
                    elif file_path.endswith('.png'): ct = 'image/png'
                    elif file_path.endswith('.json'): ct = 'application/json'
                    self.send_header('Content-Type', ct)
                    self.send_header('Content-Length', str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                else:
                    self.send_error(404)
            except:
                self.send_error(404)

    def do_POST(self):
        path = self.path.split('?')[0]

        if path == '/input':
            try:
                length = int(self.headers.get('Content-Length', 0))
                body = json.loads(self.rfile.read(length)) if length else {}
                action = body.get('action', '')

                if action == 'tap':
                    x, y = int(body['x']), int(body['y'])
                    adb_input(f'input tap {x} {y}')
                    self._send_json({'ok': True, 'action': 'tap', 'x': x, 'y': y})

                elif action == 'swipe':
                    x1, y1 = int(body['x1']), int(body['y1'])
                    x2, y2 = int(body['x2']), int(body['y2'])
                    dur = int(body.get('duration', 300))
                    adb_input(f'input swipe {x1} {y1} {x2} {y2} {dur}')
                    self._send_json({'ok': True, 'action': 'swipe'})

                elif action == 'longpress':
                    x, y = int(body['x']), int(body['y'])
                    dur = int(body.get('duration', 1000))
                    adb_input(f'input swipe {x} {y} {x} {y} {dur}')
                    self._send_json({'ok': True, 'action': 'longpress'})

                elif action == 'key':
                    keycode = int(body['keycode'])
                    adb_input(f'input keyevent {keycode}')
                    self._send_json({'ok': True, 'action': 'key', 'keycode': keycode})

                elif action == 'wake':
                    adb_input('input keyevent KEYCODE_WAKEUP')
                    time.sleep(0.5)
                    # Swipe up to dismiss lock screen
                    adb_input('input swipe 360 1400 360 600 300')
                    self._send_json({'ok': True, 'action': 'wake'})

                elif action == 'text':
                    text = body.get('text', '')
                    if text:
                        # Escape for shell
                        safe = text.replace("'", "'\\''")
                        adb_input(f"input text '{safe}'")
                    self._send_json({'ok': True, 'action': 'text'})

                else:
                    self._send_json({'error': f'unknown action: {action}'}, 400)

            except Exception as e:
                self._send_json({'error': str(e)}, 500)
        else:
            self.send_error(404)


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    server = ThreadedHTTPServer(('0.0.0.0', PORT), RemoteHandler)
    print(f"WebRemote: Phone remote viewer on :{PORT}")
    print(f"WebRemote: Screen size: {SCREEN_WIDTH}x{SCREEN_HEIGHT}")
    server.serve_forever()


if __name__ == '__main__':
    main()
