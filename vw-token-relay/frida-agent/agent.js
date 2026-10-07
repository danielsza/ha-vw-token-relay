import Java from "frida-java-bridge";

// ── VW Token Relay — Frida Agent ──
// Hooks OkHttp3 BridgeInterceptor to capture OAuth + API traffic.
// Requires frida-compile to bundle frida-java-bridge (decoupled in Frida 17+).

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

        // Strategy 1: okio.Buffer
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

        // Strategy 2: FormBody
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

        // Strategy 3: classloader lookup
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

// ── Main hook installation ──
function installHooks() {
    if (!Java.available) {
        send({ type: 'status', msg: 'Java bridge imported but not available — retrying in 500ms' });
        setTimeout(installHooks, 500);
        return;
    }

    Java.perform(function () {
        var Bridge = Java.use('okhttp3.internal.http.BridgeInterceptor');
        var JLong = Java.use('java.lang.Long');
        var PEEK = JLong.parseLong('131072');
        var API_PEEK = JLong.parseLong('32768');

        Bridge.intercept.implementation = function (chain) {
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
                    return resp;
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
        };

        send({ type: 'status', msg: 'Hooks installed — token + API capture active' });
    });
}

send({ type: 'status', msg: 'Java bridge module loaded via ESM import' });
installHooks();

// ── RPC exports ──
rpc.exports = {
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
