import Java from "frida-java-bridge";

// ── VW Token Relay — Frida Agent ──
// Hooks OkHttp3 BridgeInterceptor to capture OAuth + API traffic.
// Requires frida-compile to bundle frida-java-bridge (decoupled in Frida 17+).
//
// CAPTURE-AND-UNHOOK pattern:
// ART's GC on Android 16 crashes when walking the stack through Frida's
// replaced method implementations (null CodeInfo in DecodeGcMasksOnly).
// GC typically runs ~15-20s after process start. We install hooks, capture
// the initial token burst, then restore the original implementation BEFORE
// the first GC cycle. The Python relay calls rpc.rehook() briefly before
// each keepalive wake to grab fresh tokens.

// Known API path prefixes
var API_PATHS = [
    '/oidc/', '/account/v1/', '/rrs/v1/', '/rvs/v1/', '/ev/v1/',
    '/lockunlock/v1/', '/honkandflash/', '/fas/v1/', '/climatisation/',
    '/charging/', '/mps/v1/', '/ss/v1/', '/pairing/', '/rst/v1/',
    '/res/v1/', '/vhs/', '/history/v1/', '/pair/v1/',
];

function isApiUrl(u) {
    for (var i = 0; i < API_PATHS.length; i++) {
        if (u.indexOf(API_PATHS[i]) !== -1) return true;
    }
    return false;
}

function getRequestBody(req) {
    try {
        var body = req.body();
        if (body === null) return null;

        var BufferClass = null;
        try { BufferClass = Java.use('okio.Buffer'); } catch(e) {}
        if (!BufferClass) try { BufferClass = Java.use('okhttp3.internal.okio.Buffer'); } catch(e) {}
        if (!BufferClass) try { BufferClass = Java.use('o.Buffer'); } catch(e) {}

        if (BufferClass) {
            try {
                var buffer = BufferClass.$new();
                body.writeTo(buffer);
                return buffer.readUtf8();
            } catch(e1) {}
        }

        try {
            var ActualClass = Java.use(body.getClass().getName());
            var typed = Java.cast(body, ActualClass);
            var sz = typed.size();
            var parts = [];
            for (var i = 0; i < sz; i++) {
                parts.push(typed.encodedName(i) + '=' + typed.encodedValue(i));
            }
            if (parts.length > 0) return parts.join('&');
        } catch(e2) {}

        try {
            var cl = body.getClass().getClassLoader();
            var bufCls = cl.loadClass('okio.Buffer');
            var DynBuffer = Java.use(bufCls.getName());
            var buf = DynBuffer.$new();
            body.writeTo(buf);
            return buf.readUtf8();
        } catch(e3) {}

        var ct = body.contentType();
        var cl2 = body.contentLength();
        return '(body: type=' + ct + ', len=' + cl2 + ', buffer not available)';
    } catch (e) {
        return '(error reading body: ' + e + ')';
    }
}

// ── Hook state ──
var _Bridge = null;          // Java.use handle (reusable across hook/unhook)
var _origIntercept = null;   // original .implementation ref
var _hooked = false;
var _tokenCaptured = false;
var _unhookTimer = null;
var _autoUnhookMs = 12000;   // unhook 12s after install (well before GC at ~15-20s)
var _captureUnhookMs = 3000; // unhook 3s after first token capture

function unhookInterceptor() {
    if (!_hooked || !_Bridge) return;
    try {
        Java.performNow(function () {
            _Bridge.intercept.implementation = _origIntercept;
        });
    } catch (e) {
        // If performNow fails, try direct assignment
        try { _Bridge.intercept.implementation = _origIntercept; } catch(e2) {}
    }
    _hooked = false;
    if (_unhookTimer) {
        clearTimeout(_unhookTimer);
        _unhookTimer = null;
    }
    send({ type: 'status', msg: 'Hooks removed (original implementation restored) — safe from GC crash' });
}

function installHooks() {
    if (!Java.available) {
        send({ type: 'status', msg: 'Java bridge imported but not available — retrying in 500ms' });
        setTimeout(installHooks, 500);
        return;
    }

    Java.perform(function () {
        _Bridge = Java.use('okhttp3.internal.http.BridgeInterceptor');
        var JLong = Java.use('java.lang.Long');
        var PEEK = JLong.parseLong('131072');
        var API_PEEK = JLong.parseLong('32768');

        // Save original implementation for restoration
        _origIntercept = _Bridge.intercept.implementation;
        _tokenCaptured = false;

        _Bridge.intercept.implementation = function (chain) {
            var resp;
            try {
                var req = chain.request();
                var url = req.url().toString();
                var method = req.method();
                resp = this.intercept(chain);

                // ── Authorization headers → fresh access tokens ──
                var hdrs = req.headers();
                for (var i = 0; i < hdrs.size(); i++) {
                    if (hdrs.name(i) === 'Authorization') {
                        var val = hdrs.value(i);
                        if (val.length > 50) {
                            send({ type: 'auth_header', url: url, token: val.substring(7) });
                            scheduleUnhookAfterCapture();
                        }
                        break;
                    }
                }

                // ── OIDC token responses ──
                if (url.indexOf('/oidc/') !== -1) {
                    try {
                        var reqBody = getRequestBody(req);
                        send({ type: 'token_response', url: url, method: method,
                               requestBody: reqBody, body: resp.peekBody(PEEK).string() });
                        scheduleUnhookAfterCapture();
                    } catch (e) {}
                    return resp;
                }

                // ── idToken from URL query params ──
                if (url.indexOf('idToken=') !== -1) {
                    send({ type: 'id_token_url', url: url });
                    scheduleUnhookAfterCapture();
                }

                // ── Known API responses ──
                if (isApiUrl(url)) {
                    try {
                        send({ type: 'api_response', url: url, method: method,
                               body: resp.peekBody(API_PEEK).string() });
                    } catch (e) {}
                }
            } catch (outerErr) {
                send({ type: 'hook_error', error: '' + outerErr });
            }
            return resp;
        };

        _hooked = true;
        send({ type: 'status', msg: 'Hooks installed — token + API capture active' });

        // Safety net: auto-unhook after _autoUnhookMs even if no tokens captured,
        // to prevent GC crash
        _unhookTimer = setTimeout(function () {
            if (_hooked) {
                send({ type: 'status', msg: 'Auto-unhook timer fired (no crash window) — removing hooks' });
                unhookInterceptor();
            }
        }, _autoUnhookMs);
    });
}

function scheduleUnhookAfterCapture() {
    if (_tokenCaptured) return; // already scheduled
    _tokenCaptured = true;

    // Clear the safety-net timer and set a shorter post-capture timer
    if (_unhookTimer) {
        clearTimeout(_unhookTimer);
        _unhookTimer = null;
    }

    _unhookTimer = setTimeout(function () {
        if (_hooked) {
            send({ type: 'status', msg: 'Post-capture unhook — tokens grabbed, removing hooks to prevent GC crash' });
            unhookInterceptor();
        }
    }, _captureUnhookMs);
}

send({ type: 'status', msg: 'Java bridge module loaded via ESM import' });
installHooks();

// ── RPC exports ──
rpc.exports = {
    // Re-enable hooks briefly (called by Python relay before keepalive wake)
    rehook: function () {
        if (_hooked) return JSON.stringify({ status: 'already_hooked' });
        try {
            installHooks();
            return JSON.stringify({ status: 'hooks_reinstalled' });
        } catch (e) {
            return JSON.stringify({ status: 'error', error: e.toString() });
        }
    },

    // Explicitly remove hooks
    unhook: function () {
        if (!_hooked) return JSON.stringify({ status: 'not_hooked' });
        unhookInterceptor();
        return JSON.stringify({ status: 'unhooked' });
    },

    // Check hook state
    hookStatus: function () {
        return JSON.stringify({ hooked: _hooked, tokenCaptured: _tokenCaptured });
    },

    listKeystoreAliases: function () {
        var retval = null;
        Java.performNow(function () {
            try {
                var KeyStore = Java.use('java.security.KeyStore');
                var ks = KeyStore.getInstance('AndroidKeyStore');
                ks.load(null);
                var aliases = ks.aliases();
                var result = [];
                while (aliases.hasMoreElements()) {
                    result.push(aliases.nextElement().toString());
                }
                retval = JSON.stringify(result);
            } catch (e) {
                retval = JSON.stringify({ error: e.toString() });
            }
        });
        return retval || JSON.stringify({ error: 'Java.performNow returned without setting result' });
    },

    readSharedPrefs: function (prefName) {
        var retval = null;
        Java.performNow(function () {
            try {
                var ActivityThread = Java.use('android.app.ActivityThread');
                var app = ActivityThread.currentApplication();
                var context = app.getApplicationContext();

                if (!prefName || prefName === '') {
                    var prefsDir = context.getFilesDir().getParent() + '/shared_prefs';
                    var File = Java.use('java.io.File');
                    var dir = File.$new(prefsDir);
                    var files = dir.list();
                    var names = [];
                    if (files) {
                        for (var i = 0; i < files.length; i++) {
                            names.push(files[i].toString());
                        }
                    }
                    retval = JSON.stringify({ prefs_dir: prefsDir, files: names });
                    return;
                }

                var prefs = context.getSharedPreferences(prefName, 0);
                var allEntries = prefs.getAll();
                var map = {};
                var iterator = allEntries.entrySet().iterator();
                while (iterator.hasNext()) {
                    var entry = iterator.next();
                    map[entry.getKey().toString()] = entry.getValue() !== null ? entry.getValue().toString() : null;
                }
                retval = JSON.stringify({ name: prefName, entries: map });
            } catch (e) {
                retval = JSON.stringify({ error: e.toString() });
            }
        });
        return retval || JSON.stringify({ error: 'Java.performNow returned without setting result' });
    },

    evalReactNative: function (jsCode) {
        var retval = null;
        Java.performNow(function () {
            try {
                var CatalystInstanceImpl = null;
                try { CatalystInstanceImpl = Java.use('com.facebook.react.bridge.CatalystInstanceImpl'); } catch(e) {}

                if (CatalystInstanceImpl) {
                    Java.choose('com.facebook.react.bridge.CatalystInstanceImpl', {
                        onMatch: function (instance) {
                            retval = JSON.stringify({ found: true, msg: 'CatalystInstance found but direct JS eval not available.' });
                        },
                        onComplete: function () {}
                    });
                }

                if (!retval) {
                    var ReactContext = null;
                    try { ReactContext = Java.use('com.facebook.react.bridge.ReactContext'); } catch(e) {}
                    if (ReactContext) {
                        Java.choose('com.facebook.react.bridge.ReactContext', {
                            onMatch: function (ctx) {
                                try {
                                    var modules = ctx.getNativeModules();
                                    var names = [];
                                    var iter = modules.entrySet().iterator();
                                    var count = 0;
                                    while (iter.hasNext() && count < 50) {
                                        names.push(iter.next().getKey().toString());
                                        count++;
                                    }
                                    retval = JSON.stringify({ react_modules: names, total: modules.size() });
                                } catch (e) {
                                    retval = JSON.stringify({ error: 'module enum failed: ' + e });
                                }
                            },
                            onComplete: function () {}
                        });
                    }
                }
                if (!retval) retval = JSON.stringify({ error: 'No React Native bridge found' });
            } catch (e) {
                retval = JSON.stringify({ error: e.toString() });
            }
        });
        return retval || JSON.stringify({ error: 'Java.performNow returned without setting result' });
    },

    signWithKeystore: function (dataBase64, alias) {
        var retval = null;
        Java.performNow(function () {
            try {
                var KeyStore = Java.use('java.security.KeyStore');
                var ks = KeyStore.getInstance('AndroidKeyStore');
                ks.load(null);
                var privateKey = ks.getKey(alias, null);
                if (!privateKey) {
                    retval = JSON.stringify({ error: 'No key found for alias: ' + alias });
                    return;
                }
                var Signature = Java.use('java.security.Signature');
                var sig = Signature.getInstance('SHA256withECDSA');
                sig.initSign(privateKey);
                var Base64 = Java.use('android.util.Base64');
                var inputBytes = Base64.decode(dataBase64, 0);
                sig.update(inputBytes);
                var signatureBytes = sig.sign();
                var resultB64 = Base64.encodeToString(signatureBytes, 2);
                retval = JSON.stringify({ signature: resultB64.toString(), alias: alias });
            } catch (e) {
                retval = JSON.stringify({ error: e.toString() });
            }
        });
        return retval || JSON.stringify({ error: 'Java.performNow returned without setting result' });
    },
};
