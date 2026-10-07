import Java from "frida-java-bridge";

// ── VW Token Relay — Frida Agent v3 (GC-Safe via registerClass) ──
//
// APPROACH: Instead of hooking existing Java methods with .implementation
// (which corrupts ART CodeInfo metadata → GC crash on Android 16), this
// agent creates a FRESH OkHttp Interceptor class via Java.registerClass.
//
// Why this is GC-safe:
//   .implementation changes an existing method's entry point. The ArtMethod
//   still has kAccNative=0, so GC tries to decode CodeInfo for the old
//   compiled code at the new trampoline address → crash.
//
//   Java.registerClass creates a new DEX with native methods from birth.
//   The ArtMethod has kAccNative=1, GC sees a native frame, skips CodeInfo
//   lookup entirely → no crash.
//
// The interceptor is injected into OkHttpClient instances via reflection.
// No existing methods are modified. Hooks are permanent (no unhook needed).

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

// ── Injection state ──
var _injected = false;
var _injectedCount = 0;
var _retryCount = 0;
var _maxRetries = 10;
var _tokenInterceptorInstance = null;

function installHooks() {
    if (!Java.available) {
        send({ type: 'status', msg: 'Java bridge not available yet — retrying in 500ms' });
        setTimeout(installHooks, 500);
        return;
    }

    Java.perform(function () {
        try {
            var JLong = Java.use('java.lang.Long');
            var PEEK = JLong.parseLong('131072');    // 128KB for token responses
            var API_PEEK = JLong.parseLong('32768'); // 32KB for API responses

            // ── Step 1: Register a custom OkHttp Interceptor class ──
            // This creates a NEW class with native methods — no ART corruption!
            var InterceptorIface = Java.use('okhttp3.Interceptor');

            var TokenCapture = Java.registerClass({
                name: 'com.frida.vw.TokenCapture',
                implements: [InterceptorIface],
                methods: {
                    intercept: [{
                        returnType: 'okhttp3.Response',
                        argumentTypes: ['okhttp3.Interceptor$Chain'],
                        implementation: function (chain) {
                            var req = chain.request();
                            var resp;
                            try {
                                resp = chain.proceed(req);
                            } catch (proceedErr) {
                                // Let OkHttp handle network errors normally
                                throw proceedErr;
                            }

                            try {
                                var url = req.url().toString();
                                var method = req.method();

                                // ── Authorization headers → fresh access tokens ──
                                var hdrs = req.headers();
                                for (var i = 0; i < hdrs.size(); i++) {
                                    if (hdrs.name(i) === 'Authorization') {
                                        var val = hdrs.value(i);
                                        if (val.length > 50) {
                                            send({ type: 'auth_header', url: url, token: val.substring(7) });
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
                                    } catch (e) {}
                                }

                                // ── idToken from URL query params ──
                                if (url.indexOf('idToken=') !== -1) {
                                    send({ type: 'id_token_url', url: url });
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
                        }
                    }]
                }
            });

            _tokenInterceptorInstance = TokenCapture.$new();
            send({ type: 'status', msg: 'TokenCapture interceptor class registered (native ArtMethod — GC-safe)' });

            // ── Step 2: Inject into OkHttpClient instances ──
            injectInterceptor(_tokenInterceptorInstance);

        } catch (e) {
            send({ type: 'hook_error', error: 'Hook setup failed: ' + e + '\n' + e.stack });
        }
    });
}

function injectInterceptor(interceptor) {
    Java.perform(function () {
        _injectedCount = 0;

        Java.choose('okhttp3.OkHttpClient', {
            onMatch: function (client) {
                try {
                    var clientClass = client.getClass();
                    var field = clientClass.getDeclaredField('interceptors');
                    field.setAccessible(true);
                    var currentList = field.get(client);

                    // Check if our interceptor is already injected
                    var javaList = Java.cast(currentList, Java.use('java.util.List'));
                    for (var i = 0; i < javaList.size(); i++) {
                        var existing = javaList.get(i);
                        if (existing !== null && existing.getClass().getName() === 'com.frida.vw.TokenCapture') {
                            // Already injected, skip
                            _injectedCount++;
                            return;
                        }
                    }

                    // Build new list: existing interceptors + ours at the end
                    var ArrayList = Java.use('java.util.ArrayList');
                    var newList = ArrayList.$new();
                    for (var j = 0; j < javaList.size(); j++) {
                        newList.add(javaList.get(j));
                    }
                    newList.add(interceptor);

                    // Replace the field value (works even on final fields with setAccessible)
                    field.set(client, Java.cast(newList, Java.use('java.util.List')));
                    _injectedCount++;
                } catch (e) {
                    send({ type: 'hook_error', error: 'OkHttpClient injection failed: ' + e });
                }
            },
            onComplete: function () {
                if (_injectedCount > 0) {
                    _injected = true;
                    send({ type: 'status', msg: 'Interceptor injected into ' + _injectedCount + ' OkHttpClient(s) — PERMANENT, no unhook needed!' });
                } else {
                    _retryCount++;
                    if (_retryCount <= _maxRetries) {
                        send({ type: 'status', msg: 'No OkHttpClient found yet (attempt ' + _retryCount + '/' + _maxRetries + ') — retrying in 2s' });
                        setTimeout(function () {
                            injectInterceptor(interceptor);
                        }, 2000);
                    } else {
                        send({ type: 'hook_error', error: 'Could not find OkHttpClient after ' + _maxRetries + ' attempts' });
                    }
                }
            }
        });
    });
}

send({ type: 'status', msg: 'Agent v3 loaded — Java.registerClass approach (GC-safe)' });
installHooks();

// ── RPC exports ──
// rehook/unhook are no-ops since our interceptor is permanent and GC-safe.
// listKeystoreAliases, readSharedPrefs, signWithKeystore use Java.performNow
// which does NOT modify ArtMethods — completely safe.
rpc.exports = {
    rehook: function () {
        // No-op: our interceptor is permanent, no need to reinstall
        if (!_injected && _tokenInterceptorInstance) {
            // But if not yet injected, try again
            try {
                injectInterceptor(_tokenInterceptorInstance);
                return JSON.stringify({ status: 'retry_injection', injected: _injected, count: _injectedCount });
            } catch (e) {
                return JSON.stringify({ status: 'retry_failed', error: e.toString() });
            }
        }
        return JSON.stringify({ status: 'interceptor_permanent', injected: _injected, count: _injectedCount });
    },

    unhook: function () {
        // No-op: no need to unhook — interceptor is GC-safe
        return JSON.stringify({ status: 'interceptor_permanent', msg: 'GC-safe — no unhook needed' });
    },

    hookStatus: function () {
        return JSON.stringify({ hooked: _injected, injectedClients: _injectedCount, approach: 'registerClass_v3' });
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
