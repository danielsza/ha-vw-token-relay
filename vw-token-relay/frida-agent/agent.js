import Java from "frida-java-bridge";

// ── VW Token Relay — Frida Agent v3.1 (Native SSL Hooks) ──
//
// Hooks BoringSSL's SSL_write/SSL_read via Interceptor.attach (native C
// function patching). Forces HTTP/1.1 by modifying ALPN negotiation.
// Parses HTTP/1.1 traffic at the TLS layer to capture tokens.
//
// Why this is GC-safe:
//   Interceptor.attach patches the first instruction of NATIVE functions
//   (SSL_write, SSL_read, etc.) — no ART method structs touched, no
//   CodeInfo corruption, no GC crash.
//
// Java is used ONLY for RPC exports (readSharedPrefs, signWithKeystore)
// via Java.performNow — one-shot JNI calls, no ArtMethod modification.
//
// No .implementation. No Java.registerClass. Pure native interception.

// ── Config ──
var API_PATHS = [
    '/oidc/', '/account/v1/', '/rrs/v1/', '/rvs/v1/', '/ev/v1/',
    '/lockunlock/v1/', '/honkandflash/', '/fas/v1/', '/climatisation/',
    '/charging/', '/mps/v1/', '/ss/v1/', '/pairing/', '/rst/v1/',
    '/res/v1/', '/vhs/', '/history/v1/', '/pair/v1/',
];

function isApiPath(p) {
    for (var i = 0; i < API_PATHS.length; i++) {
        if (p.indexOf(API_PATHS[i]) !== -1) return true;
    }
    return false;
}

// ── Connection state per SSL* pointer ──
// Tracks request info so we can correlate responses with their URLs.
var conns = {};

// Counters for status reporting
var _authCount = 0;
var _tokenRespCount = 0;
var _apiRespCount = 0;
var _hooksInstalled = false;
var _alpnForced = false;

// ── Install native SSL hooks ──
function installNativeHooks() {
    var SSL_write = Module.findExportByName(null, 'SSL_write');
    var SSL_read  = Module.findExportByName(null, 'SSL_read');

    if (!SSL_write || !SSL_read) {
        send({ type: 'hook_error', error: 'Cannot find SSL_write/SSL_read exports' });
        return;
    }

    // ── Force HTTP/1.1 via ALPN ──
    // This makes all connections use plain-text HTTP/1.1 instead of binary
    // HTTP/2, so we can parse traffic as simple text.
    var SSL_set_alpn = Module.findExportByName(null, 'SSL_set_alpn_protos');
    if (SSL_set_alpn) {
        Interceptor.attach(SSL_set_alpn, {
            onEnter: function (args) {
                try {
                    var protosLen = args[2].toInt32();
                    if (protosLen <= 0 || protosLen > 256) return;
                    var protosBytes = args[1].readByteArray(protosLen);
                    if (!protosBytes) return;
                    var arr = new Uint8Array(protosBytes);
                    // Check if h2 is offered (byte sequence: 0x02 0x68 0x32)
                    var hasH2 = false;
                    for (var i = 0; i < arr.length - 2; i++) {
                        if (arr[i] === 0x02 && arr[i+1] === 0x68 && arr[i+2] === 0x32) {
                            hasH2 = true;
                            break;
                        }
                    }
                    if (hasH2) {
                        // Replace with http/1.1 only: \x08http/1.1
                        var h11 = Memory.alloc(9);
                        h11.writeByteArray([0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31]);
                        args[1] = h11;
                        args[2] = ptr(9);
                        this._mem = h11; // prevent GC
                        _alpnForced = true;
                    }
                } catch (e) {}
            }
        });
        send({ type: 'status', msg: 'ALPN hook active — will force HTTP/1.1' });
    } else {
        send({ type: 'status', msg: 'WARN: SSL_set_alpn_protos not found — HTTP/2 traffic may be missed' });
    }

    // ── Hook SSL_write: capture outgoing HTTP requests ──
    Interceptor.attach(SSL_write, {
        onEnter: function (args) {
            var num = args[2].toInt32();
            if (num < 16 || num > 65536) return; // skip tiny/huge writes
            try {
                var data = args[1].readUtf8String(num);
                if (!data) return;

                // Quick check: is this an HTTP/1.x request line?
                if (data.charCodeAt(0) < 0x41 || data.charCodeAt(0) > 0x5A) return; // not uppercase letter
                var nlPos = data.indexOf('\r\n');
                if (nlPos < 10 || nlPos > 2048) return;

                var reqLine = data.substring(0, nlPos);
                var reqMatch = reqLine.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) ([^\s]+) HTTP\/1\.[01]$/);
                if (!reqMatch) return;

                var method = reqMatch[1];
                var path = reqMatch[2];

                // Extract Host header
                var hostMatch = data.match(/\r\nHost: ([^\r\n]+)/);
                var host = hostMatch ? hostMatch[1].trim() : 'unknown';
                var url = 'https://' + host + path;

                // ── Authorization header ──
                var authMatch = data.match(/\r\nAuthorization: Bearer ([^\r\n]+)/);
                if (authMatch && authMatch[1].length > 50) {
                    send({ type: 'auth_header', url: url, token: authMatch[1] });
                    _authCount++;
                }

                // ── idToken in URL ──
                if (path.indexOf('idToken=') !== -1) {
                    send({ type: 'id_token_url', url: url });
                }

                // ── Extract POST body ──
                var reqBody = null;
                if (method === 'POST') {
                    var bodyStart = data.indexOf('\r\n\r\n');
                    if (bodyStart !== -1 && bodyStart + 4 < data.length) {
                        reqBody = data.substring(bodyStart + 4);
                    }
                }

                // Store for response correlation
                var key = args[0].toString();
                conns[key] = {
                    url: url,
                    host: host,
                    method: method,
                    path: path,
                    reqBody: reqBody,
                    // Response accumulation
                    respRaw: '',
                    headersParsed: false,
                    contentLength: -1,
                    isChunked: false,
                    isGzip: false,
                    bodyStart: -1,
                    statusCode: 0,
                };
            } catch (e) {}
        }
    });

    // ── Hook SSL_read: capture incoming HTTP responses ──
    Interceptor.attach(SSL_read, {
        onEnter: function (args) {
            this._ssl = args[0];
            this._buf = args[1];
        },
        onLeave: function (retval) {
            var bytesRead = retval.toInt32();
            if (bytesRead <= 0) return;

            var key = this._ssl.toString();
            var conn = conns[key];

            // If no tracked request for this connection, check for HTTP response start
            if (!conn) {
                try {
                    // Peek at the first few bytes
                    var peek = this._buf.readUtf8String(Math.min(bytesRead, 20));
                    if (peek && peek.indexOf('HTTP/1.') === 0) {
                        // Untracked response — create minimal entry
                        conn = {
                            url: 'unknown', host: 'unknown', method: '?',
                            path: '?', reqBody: null, respRaw: '',
                            headersParsed: false, contentLength: -1,
                            isChunked: false, isGzip: false, bodyStart: -1, statusCode: 0,
                        };
                        conns[key] = conn;
                    } else {
                        return;
                    }
                } catch (e) { return; }
            }

            try {
                var chunk = this._buf.readUtf8String(bytesRead);
                if (!chunk) return;
                conn.respRaw += chunk;
            } catch (e) {
                // Binary data — if gzip, we can't easily parse
                return;
            }

            // Parse headers if we haven't yet
            if (!conn.headersParsed) {
                var hdrEnd = conn.respRaw.indexOf('\r\n\r\n');
                if (hdrEnd === -1) return; // need more data for headers

                conn.headersParsed = true;
                conn.bodyStart = hdrEnd + 4;

                var hdrStr = conn.respRaw.substring(0, hdrEnd);

                // Status code
                var stMatch = hdrStr.match(/^HTTP\/1\.[01] (\d+)/);
                conn.statusCode = stMatch ? parseInt(stMatch[1]) : 0;

                // Content-Length
                var clMatch = hdrStr.match(/\r\nContent-Length:\s*(\d+)/i);
                conn.contentLength = clMatch ? parseInt(clMatch[1]) : -1;

                // Transfer-Encoding / Content-Encoding
                conn.isChunked = /\r\nTransfer-Encoding:\s*chunked/i.test(hdrStr);
                conn.isGzip = /\r\nContent-Encoding:\s*gzip/i.test(hdrStr);
            }

            // Check if response body is complete
            var bodyBytes = conn.respRaw.length - conn.bodyStart;

            var complete = false;
            if (conn.contentLength >= 0 && bodyBytes >= conn.contentLength) {
                complete = true;
            } else if (conn.isChunked) {
                var bodyStr = conn.respRaw.substring(conn.bodyStart);
                if (bodyStr.indexOf('\r\n0\r\n') !== -1) {
                    complete = true;
                }
            }
            // Safety cap: don't accumulate more than 256KB
            if (bodyBytes > 262144) {
                complete = true;
            }

            if (complete) {
                processCompleteResponse(conn);
                delete conns[key];
            }
        }
    });

    _hooksInstalled = true;
    send({ type: 'status', msg: 'Native SSL hooks installed — capturing HTTP traffic (GC-safe!)' });
}

// ── Process a complete HTTP response ──
function processCompleteResponse(conn) {
    if (conn.bodyStart < 0) return;

    var body = conn.respRaw.substring(conn.bodyStart);

    // For chunked encoding, strip chunk framing
    if (conn.isChunked && !conn.isGzip) {
        body = dechunk(body);
    }

    // If gzip, try native decompression
    if (conn.isGzip) {
        try {
            body = nativeGunzip(conn.respRaw, conn.bodyStart);
        } catch (e) {
            // Can't decompress — check if body has readable tokens anyway
            // (sometimes Content-Encoding header is wrong)
            if (body.indexOf('access_token') === -1) return;
        }
    }

    if (!body || body.length === 0) return;

    var url = conn.url;
    var isOidc = url.indexOf('/oidc/') !== -1;
    var hasToken = body.indexOf('access_token') !== -1 || body.indexOf('id_token') !== -1;
    var isApi = isApiPath(conn.path);

    // ── OIDC token response ──
    if (isOidc || hasToken) {
        // Extract JSON body
        var jsonStart = body.indexOf('{');
        if (jsonStart !== -1) {
            var jsonBody = body.substring(jsonStart);
            send({ type: 'token_response', url: url, method: conn.method,
                   requestBody: conn.reqBody, body: jsonBody });
            _tokenRespCount++;
        }
    }

    // ── API response ──
    if (isApi && !isOidc) {
        var apiJsonStart = body.indexOf('{');
        if (apiJsonStart === -1) apiJsonStart = body.indexOf('[');
        if (apiJsonStart !== -1) {
            var apiBody = body.substring(apiJsonStart);
            if (apiBody.length > 131072) apiBody = apiBody.substring(0, 131072);
            send({ type: 'api_response', url: url, method: conn.method, body: apiBody });
            _apiRespCount++;
        }
    }
}

// ── Strip HTTP chunked transfer encoding ──
function dechunk(raw) {
    var result = '';
    var pos = 0;
    while (pos < raw.length) {
        var nlPos = raw.indexOf('\r\n', pos);
        if (nlPos === -1) break;
        var sizeStr = raw.substring(pos, nlPos).trim();
        var chunkSize = parseInt(sizeStr, 16);
        if (isNaN(chunkSize) || chunkSize === 0) break;
        var chunkStart = nlPos + 2;
        if (chunkStart + chunkSize > raw.length) {
            result += raw.substring(chunkStart);
            break;
        }
        result += raw.substring(chunkStart, chunkStart + chunkSize);
        pos = chunkStart + chunkSize + 2; // skip chunk data + \r\n
    }
    return result || raw; // fallback to raw if dechunking fails
}

// ── Native gzip decompression via zlib ──
function nativeGunzip(fullResp, bodyStartOffset) {
    var inflateInit2Ptr = Module.findExportByName(null, 'inflateInit2_');
    var inflatePtr      = Module.findExportByName(null, 'inflate');
    var inflateEndPtr   = Module.findExportByName(null, 'inflateEnd');

    if (!inflateInit2Ptr || !inflatePtr || !inflateEndPtr) {
        throw new Error('zlib not found');
    }

    var inflateInit2 = new NativeFunction(inflateInit2Ptr, 'int', ['pointer', 'int', 'pointer', 'int']);
    var inflateF     = new NativeFunction(inflatePtr,      'int', ['pointer', 'int']);
    var inflateEnd   = new NativeFunction(inflateEndPtr,   'int', ['pointer']);

    // Extract raw body bytes
    var bodyStr = fullResp.substring(bodyStartOffset);
    var inLen = bodyStr.length;
    var inBuf = Memory.alloc(inLen);
    inBuf.writeUtf8String(bodyStr);

    // Output buffer (4x input)
    var outLen = inLen * 4;
    if (outLen < 16384) outLen = 16384;
    var outBuf = Memory.alloc(outLen);

    // z_stream struct (112 bytes on arm64)
    var stream = Memory.alloc(128);
    stream.writeByteArray(new Array(128).fill(0));

    // z_stream fields: next_in(ptr), avail_in(uint), total_in(ulong),
    //                  next_out(ptr), avail_out(uint), ...
    stream.writePointer(inBuf);                          // next_in
    stream.add(8).writeU32(inLen);                       // avail_in
    stream.add(16).writePointer(outBuf);                 // next_out (offset 16 on 64-bit)
    stream.add(24).writeU32(outLen);                     // avail_out

    // ZLIB version string
    var zlibVer = Memory.allocUtf8String('1.2.11');

    // inflateInit2_(stream, windowBits=15+16=31 for gzip, version, stream_size)
    var ret = inflateInit2(stream, 31, zlibVer, 128);
    if (ret !== 0) throw new Error('inflateInit2 failed: ' + ret);

    // inflate with Z_FINISH (4)
    ret = inflateF(stream, 4);

    // Read output regardless (Z_STREAM_END=1 is success, Z_OK=0 means partial)
    var bytesWritten = outLen - stream.add(24).readU32();
    inflateEnd(stream);

    if (bytesWritten > 0) {
        return outBuf.readUtf8String(bytesWritten);
    }
    throw new Error('inflate produced 0 bytes, ret=' + ret);
}

// ── Connection cleanup timer ──
// Remove stale connections every 30s to prevent memory leaks
setInterval(function () {
    var now = Date.now();
    var keys = Object.keys(conns);
    if (keys.length > 200) {
        // Too many tracked connections — clear old ones
        var sorted = keys.sort();
        for (var i = 0; i < sorted.length - 50; i++) {
            delete conns[sorted[i]];
        }
    }
}, 30000);

// ── Boot ──
send({ type: 'status', msg: 'Agent v3.1 loaded — Native SSL approach (GC-safe, no ART modification)' });
installNativeHooks();

// ── RPC exports ──
// rehook/unhook are no-ops: native hooks are permanent and GC-safe.
// Java RPC exports use Java.performNow (one-shot JNI, no ArtMethod modification).
rpc.exports = {
    rehook: function () {
        return JSON.stringify({
            status: 'native_hooks_permanent',
            hooksInstalled: _hooksInstalled,
            alpnForced: _alpnForced,
            stats: { auth: _authCount, tokenResp: _tokenRespCount, apiResp: _apiRespCount }
        });
    },

    unhook: function () {
        return JSON.stringify({ status: 'native_hooks_permanent', msg: 'GC-safe — no unhook needed' });
    },

    hookStatus: function () {
        return JSON.stringify({
            hooked: _hooksInstalled,
            approach: 'native_ssl_v3.1',
            alpnForced: _alpnForced,
            stats: { auth: _authCount, tokenResp: _tokenRespCount, apiResp: _apiRespCount }
        });
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
