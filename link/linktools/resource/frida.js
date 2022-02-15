(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
});

var e = function() {
  function e() {
    this.debug = 1, this.info = 2, this.warning = 3, this.error = 4, this.$level = this.info;
  }
  return Object.defineProperty(e.prototype, "level", {
    get: function() {
      return this.$level;
    },
    enumerable: !1,
    configurable: !0
  }), e.prototype.setLevel = function(e) {
    this.$level = e, this.d("Set log level: " + e);
  }, e.prototype.d = function(e, r) {
    void 0 === r && (r = null), this.$level <= this.debug && send({
      log: {
        level: "debug",
        tag: r,
        message: e
      }
    });
  }, e.prototype.i = function(e, r) {
    void 0 === r && (r = null), this.$level <= this.info && send({
      log: {
        level: "info",
        tag: r,
        message: e
      }
    });
  }, e.prototype.w = function(e, r) {
    void 0 === r && (r = null), this.$level <= this.warning && send({
      log: {
        level: "warning",
        tag: r,
        message: e
      }
    });
  }, e.prototype.e = function(e, r) {
    void 0 === r && (r = null), this.$level <= this.error && send({
      log: {
        level: "error",
        tag: r,
        message: e
      }
    });
  }, e;
}(), r = function() {
  function e() {}
  return e.prototype.load = function(e, r) {
    Object.defineProperties(globalThis, {
      parameters: {
        enumerable: !0,
        value: r
      }
    });
    for (var t = 0, n = e; t < n.length; t++) {
      var l = n[t];
      try {
        (0, eval)(l.source);
      } catch (e) {
        throw new Error("Unable to load ".concat(l.filename, ": ").concat(e.stack));
      }
    }
  }, e;
}(), t = new r;

rpc.exports = {
  loadScripts: t.load.bind(t)
};

var n = require("./lib/c"), l = require("./lib/java"), o = require("./lib/android"), i = require("./lib/objc"), a = new e, u = new n.CHelper, s = new l.JavaHelper, c = new o.AndroidHelper, v = new i.ObjCHelper;

Object.defineProperties(globalThis, {
  Log: {
    enumerable: !0,
    value: a
  },
  CHelper: {
    enumerable: !0,
    value: u
  },
  JavaHelper: {
    enumerable: !0,
    value: s
  },
  AndroidHelper: {
    enumerable: !0,
    value: c
  },
  ObjCHelper: {
    enumerable: !0,
    value: v
  },
  ignoreError: {
    enumerable: !1,
    value: function(e, r) {
      void 0 === r && (r = void 0);
      try {
        return e();
      } catch (e) {
        return a.d("Catch ignored error. " + e), r;
      }
    }
  },
  pretty2String: {
    enumerable: !1,
    value: function(e) {
      return (e = pretty2Json(e)) instanceof Object ? JSON.stringify(e) : e;
    }
  },
  pretty2Json: {
    enumerable: !1,
    value: function(e) {
      if (!(e instanceof Object)) return e;
      if (Array.isArray(e) || s.isArray(e)) {
        for (var r = [], t = 0; t < e.length; t++) r.push(pretty2Json(e[t]));
        return r;
      }
      return ignoreError((function() {
        return e.toString();
      }), void 0);
    }
  }
});

},{"./lib/android":2,"./lib/c":3,"./lib/java":4,"./lib/objc":5}],2:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.AndroidHelper = void 0;

var e = function() {
  function e() {}
  return e.prototype.setWebviewDebuggingEnabled = function() {
    Log.i("======================================================\r\nAndroid Enable Webview Debugging                      \r\n======================================================"), 
    Java.perform((function() {
      JavaHelper.hookMethods("android.webkit.WebView", "loadUrl", (function(e, n) {
        return Log.d("setWebContentsDebuggingEnabled: " + e), e.setWebContentsDebuggingEnabled(!0), 
        this.apply(e, n);
      }));
    }));
    try {
      JavaHelper.hookMethods("com.uc.webview.export.WebView", "loadUrl", (function(e, n) {
        return Log.d("setWebContentsDebuggingEnabled: " + e), e.setWebContentsDebuggingEnabled(!0), 
        this.apply(e, n);
      }));
    } catch (e) {
      Log.d("Hook com.uc.webview.export.WebView.loadUrl error: " + e, "[-]");
    }
  }, e.prototype.bypassSslPinningLite = function() {
    Log.i("======================================================\r\nAndroid Bypass ssl pinning                           \r\n======================================================"), 
    Java.perform((function() {
      try {
        var e = Java.use("java.util.Arrays");
        JavaHelper.hookMethods("com.android.org.conscrypt.TrustManagerImpl", "checkServerTrusted", (function(n, r) {
          if (Log.d("Bypassing TrustManagerImpl checkServerTrusted"), "void" != this.returnType.type) return "pointer" == this.returnType.type && "java.util.List" == this.returnType.className ? e.asList(r[0]) : void 0;
        }));
      } catch (e) {
        Log.d("Hook com.android.org.conscrypt.TrustManagerImpl.checkTrusted error: " + e, "[-]");
      }
      try {
        JavaHelper.hookMethods("com.google.android.gms.org.conscrypt.Platform", "checkServerTrusted", (function(e, n) {
          Log.d("Bypassing Platform checkServerTrusted {1}");
        }));
      } catch (e) {
        Log.d("Hook com.google.android.gms.org.conscrypt.Platform.checkServerTrusted error: " + e, "[-]");
      }
      try {
        JavaHelper.hookMethods("com.android.org.conscrypt.Platform", "checkServerTrusted", (function(e, n) {
          Log.d("Bypassing Platform checkServerTrusted {2}");
        }));
      } catch (e) {
        Log.d("Hook com.android.org.conscrypt.Platform.checkServerTrusted error: " + e, "[-]");
      }
    }));
  }, e.prototype.bypassSslPinning = function() {
    Log.i("======================================================\r\nAndroid Bypass for various Certificate Pinning methods\r\n======================================================"), 
    Java.perform((function() {
      var e = [ Java.registerClass({
        name: "xxx.xxx.xxx.TrustManager",
        implements: [ Java.use("javax.net.ssl.X509TrustManager") ],
        methods: {
          checkClientTrusted: function(e, n) {},
          checkServerTrusted: function(e, n) {},
          getAcceptedIssuers: function() {
            return [];
          }
        }
      }).$new() ];
      try {
        JavaHelper.hookMethod("javax.net.ssl.SSLContext", "init", [ "[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom" ], (function(n, r) {
          return Log.d("Bypassing Trustmanager (Android < 7) pinner"), r[1] = e, this.apply(n, r);
        }));
      } catch (e) {
        Log.d("TrustManager (Android < 7) pinner not found", "[-]");
      }
      try {
        JavaHelper.hookMethods("okhttp3.CertificatePinner", "check", (function(e, n) {
          Log.d("Bypassing OkHTTPv3 {1}: " + n[0]);
        }));
      } catch (e) {
        Log.d("OkHTTPv3 {1} pinner not found: " + e, "[-]");
      }
      try {
        JavaHelper.hookMethod("okhttp3.CertificatePinner", "check$okhttp", [ "java.lang.String", "kotlin.jvm.functions.Function0" ], (function(e, n) {
          Log.d("Bypassing OkHTTPv3 {4}: " + n[0]);
        }));
      } catch (e) {
        Log.d("OkHTTPv3 {4} pinner not found: " + e, "[-]");
      }
      try {
        JavaHelper.hookMethods("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier", "verify", (function(e, n) {
          return Log.d("Bypassing Trustkit {1}: " + n[0]), !0;
        }));
      } catch (e) {
        Log.d("Trustkit {1} pinner not found: " + e, "[-]");
      }
      try {
        JavaHelper.hookMethods("com.datatheorem.android.trustkit.pinning.PinningTrustManager", "checkServerTrusted", (function(e, n) {
          Log.d("Bypassing Trustkit {3}");
        }));
      } catch (e) {
        Log.d("Trustkit {3} pinner not found: " + e, "[-]");
      }
      try {
        var n = Java.use("java.util.ArrayList");
        JavaHelper.hookMethods("com.android.org.conscrypt.TrustManagerImpl", "checkTrustedRecursive", (function(e, r) {
          return Log.d("Bypassing TrustManagerImpl (Android > 7) checkTrustedRecursive check: " + r[3]), 
          n.$new();
        }));
      } catch (e) {
        Log.d("TrustManagerImpl (Android > 7) checkTrustedRecursive check not found: " + e, "[-]");
      }
      try {
        JavaHelper.hookMethods("com.android.org.conscrypt.TrustManagerImpl", "verifyChain", (function(e, n) {
          return Log.d("Bypassing TrustManagerImpl (Android > 7) verifyChain check: " + n[2]), 
          n[0];
        }));
      } catch (e) {
        Log.d("TrustManagerImpl (Android > 7) verifyChain check not found: " + e, "[-]");
      }
      try {
        JavaHelper.hookMethods("appcelerator.https.PinningTrustManager", "checkServerTrusted", (function() {
          Log.d("Bypassing Appcelerator PinningTrustManager");
        }));
      } catch (e) {
        Log.d("Appcelerator PinningTrustManager pinner not found: " + e, "[-]");
      }
      try {
        JavaHelper.hookMethods("io.fabric.sdk.android.services.network.PinningTrustManager", "checkServerTrusted", (function() {
          Log.d("Bypassing Fabric PinningTrustManager");
        }));
      } catch (e) {
        Log.d("Fabric PinningTrustManager pinner not found: " + e, "[-]");
      }
      try {
        JavaHelper.hookMethods("com.android.org.conscrypt.OpenSSLSocketImpl", "verifyCertificateChain", (function() {
          Log.d("Bypassing OpenSSLSocketImpl Conscrypt {1}");
        }));
      } catch (e) {
        Log.d("OpenSSLSocketImpl Conscrypt {1} pinner not found: " + e, "[-]");
      }
      try {
        JavaHelper.hookMethods("com.android.org.conscrypt.OpenSSLEngineSocketImpl", "verifyCertificateChain", (function(e, n) {
          Log.d("Bypassing OpenSSLEngineSocketImpl Conscrypt: " + (n.length >= 2 ? n[1] : null));
        }));
      } catch (e) {
        Log.d("OpenSSLEngineSocketImpl Conscrypt pinner not found: " + e, "[-]");
      }
      try {
        JavaHelper.hookMethods("org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl", "verifyCertificateChain", (function(e, n) {
          Log.d("Bypassing OpenSSLSocketImpl Apache Harmony");
        }));
      } catch (e) {
        Log.d("OpenSSLSocketImpl Apache Harmony pinner not found: " + e, "[-]");
      }
      try {
        JavaHelper.hookMethod("nl.xservices.plugins.sslCertificateChecker", "execute", [ "java.lang.String", "org.json.JSONArray", "org.apache.cordova.CallbackContext" ], (function(e, n) {
          return Log.d("Bypassing PhoneGap sslCertificateChecker: " + n[0]), !0;
        }));
      } catch (e) {
        Log.d("PhoneGap sslCertificateChecker pinner not found: " + e, "[-]");
      }
      try {
        var r = Java.use("com.worklight.wlclient.api.WLClient");
        JavaHelper.hookMethods(r.getInstance(), "pinTrustedCertificatePublicKey", (function(e, n) {
          Log.d("Bypassing IBM MobileFirst pinTrustedCertificatePublicKey {1}: " + n[0]);
        }));
      } catch (e) {
        Log.d("IBM MobileFirst pinTrustedCertificatePublicKey {1} pinner not found: " + e, "[-]");
      }
      try {
        JavaHelper.hookMethods("com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning", "verify", (function(e, n) {
          Log.d("Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {1}: " + n[0]);
        }));
      } catch (e) {
        Log.d("IBM WorkLight HostNameVerifierWithCertificatePinning {1} pinner not found: " + e, "[-]");
      }
      try {
        JavaHelper.hookMethod("com.android.org.conscrypt.CertPinManager", "checkChainPinning", [ "java.lang.String", "java.util.List" ], (function(e, n) {
          return Log.d("Bypassing Conscrypt CertPinManager: " + n[0]), !0;
        }));
      } catch (e) {
        Log.d("Conscrypt CertPinManager pinner not found: " + e, "[-]");
      }
      try {
        JavaHelper.hookMethod("com.android.org.conscrypt.CertPinManager", "isChainValid", [ "java.lang.String", "java.util.List" ], (function(e, n) {
          return Log.d("Bypassing Conscrypt CertPinManager (Legacy): " + n[0]), !0;
        }));
      } catch (e) {
        Log.d("Conscrypt CertPinManager (Legacy) pinner not found: " + e, "[-]");
      }
      try {
        JavaHelper.hookMethod("com.commonsware.cwac.netsecurity.conscrypt.CertPinManager", "isChainValid", [ "java.lang.String", "java.util.List" ], (function(e, n) {
          return Log.d("Bypassing CWAC-Netsecurity CertPinManager: " + n[0]), !0;
        }));
      } catch (e) {
        Log.d("CWAC-Netsecurity CertPinManager pinner not found: " + e, "[-]");
      }
      try {
        JavaHelper.hookMethod("com.worklight.androidgap.plugin.WLCertificatePinningPlugin", "execute", [ "java.lang.String", "org.json.JSONArray", "org.apache.cordova.CallbackContext" ], (function(e, n) {
          return Log.d("Bypassing Worklight Androidgap WLCertificatePinningPlugin: " + n[0]), 
          !0;
        }));
      } catch (e) {
        Log.d("Worklight Androidgap WLCertificatePinningPlugin pinner not found: " + e, "[-]");
      }
      try {
        JavaHelper.hookMethods("io.netty.handler.ssl.util.FingerprintTrustManagerFactory", "checkTrusted", (function(e, n) {
          Log.d("Bypassing Netty FingerprintTrustManagerFactory");
        }));
      } catch (e) {
        Log.d("Netty FingerprintTrustManagerFactory pinner not found: " + e, "[-]");
      }
      try {
        JavaHelper.hookMethods("com.squareup.okhttp.CertificatePinner", "check", (function(e, n) {
          Log.d("Bypassing Squareup CertificatePinner {1}: " + n[0]);
        }));
      } catch (e) {
        Log.d("Squareup CertificatePinner {1} pinner not found: " + e, "[-]");
      }
      try {
        JavaHelper.hookMethods("com.squareup.okhttp.internal.tls.OkHostnameVerifier", "verify", (function(e, n) {
          return Log.d("Bypassing Squareup OkHostnameVerifier {1}: " + n[0]), !0;
        }));
      } catch (e) {
        Log.d("Squareup OkHostnameVerifier check not found: " + e, "[-]");
      }
      try {
        JavaHelper.hookMethods("com.android.okhttp.internal.tls.OkHostnameVerifier", "verify", (function(e, n) {
          return Log.d("Bypassing android OkHostnameVerifier {2}: " + n[0]), !0;
        }));
      } catch (e) {
        Log.d("android OkHostnameVerifier check not found: " + e, "[-]");
      }
      try {
        JavaHelper.hookMethods("okhttp3.internal.tls.OkHostnameVerifier", "verify", (function(e, n) {
          return Log.d("Bypassing okhttp3 OkHostnameVerifier {3}: " + n[0]), !0;
        }));
      } catch (e) {
        Log.d("okhttp3 OkHostnameVerifier check not found: " + e, "[-]");
      }
      try {
        JavaHelper.hookMethods("android.webkit.WebViewClient", "onReceivedSslError", (function(e, n) {
          Log.d("Bypassing Android WebViewClient check {1}");
        }));
      } catch (e) {
        Log.d("Android WebViewClient {1} check not found: " + e, "[-]");
      }
      try {
        JavaHelper.hookMethods("android.webkit.WebViewClient", "onReceivedError", (function(e, n) {
          Log.d("Bypassing Android WebViewClient check {3}");
        }));
      } catch (e) {
        Log.d("Android WebViewClient {3} check not found: " + e, "[-]");
      }
      try {
        JavaHelper.hookMethod("org.apache.cordova.CordovaWebViewClient", "onReceivedSslError", [ "android.webkit.WebView", "android.webkit.SslErrorHandler", "android.net.http.SslError" ], (function(e, n) {
          Log.d("Bypassing Apache Cordova WebViewClient check"), n[3].proceed();
        }));
      } catch (e) {
        Log.d("Apache Cordova WebViewClient check not found: " + e, "[-]");
      }
      try {
        JavaHelper.hookMethods("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier", "verify", (function(e, n) {
          Log.d("Bypassing Boye AbstractVerifier check: " + n[0]);
        }));
      } catch (e) {
        Log.d("Boye AbstractVerifier check not found: " + e, "[-]");
      }
      try {
        JavaHelper.hookMethod("org.apache.http.conn.ssl.AbstractVerifier", "verify", [ "java.lang.String", "[Ljava.lang.String;", "[Ljava.lang.String;", "boolean" ], (function(e, n) {
          Log.d("Bypassing Apache AbstractVerifier check: " + n[0]);
        }));
      } catch (e) {
        Log.d("Apache AbstractVerifier check not found: " + e, "[-]");
      }
      try {
        JavaHelper.hookMethod("org.chromium.net.impl.CronetEngineBuilderImpl", "enablePublicKeyPinningBypassForLocalTrustAnchors", [ "boolean" ], (function(e, n) {
          return Log.i("[+] Disabling Public Key pinning for local trust anchors in Chromium Cronet"), 
          n[0] = !0, this.apply(e, n);
        }));
      } catch (e) {
        Log.d("Chromium Cronet pinner not found: " + e, "[-]");
      }
      try {
        JavaHelper.hookMethods("diefferson.http_certificate_pinning.HttpCertificatePinning", "checkConnexion", (function(e, n) {
          return Log.d("Bypassing Flutter HttpCertificatePinning : " + n[0]), !0;
        }));
      } catch (e) {
        Log.d("Flutter HttpCertificatePinning pinner not found: " + e, "[-]");
      }
      try {
        JavaHelper.hookMethods("javax.net.ssl.SSLPeerUnverifiedException", "$init", (function(e, n) {
          Log.w("Unexpected SSLPeerUnverifiedException occurred, trying to patch it dynamically...", "[!]");
          var r = Java.use("java.lang.Thread").currentThread().getStackTrace(), t = r.findIndex((function(e) {
            return "javax.net.ssl.SSLPeerUnverifiedException" === e.getClassName();
          })), o = r[t + 1], i = o.getClassName(), a = o.getMethodName();
          return JavaHelper.hookMethods(i, a, (function(e, n) {
            return "void" == this.returnType.type ? void 0 : "boolean" === this.returnType.type || null;
          })), this.apply(e, n);
        }));
      } catch (e) {
        Log.d("SSLPeerUnverifiedException not found: " + e, "[-]");
      }
    }));
  }, e;
}();

exports.AndroidHelper = e;

},{}],3:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.CHelper = void 0;

var t = function() {
  function t() {
    this.$funcCaches = {};
  }
  return Object.defineProperty(t.prototype, "dlopen", {
    get: function() {
      return this.getExportFunction("dlopen", "pointer", [ "pointer", "int" ]);
    },
    enumerable: !1,
    configurable: !0
  }), t.prototype.getExportFunction = function(t, e, r) {
    var n = t + "|" + e.toString() + "|" + r.toString();
    if (n in this.$funcCaches) return this.$funcCaches[n];
    var o = Module.findExportByName(null, t);
    if (null === o) throw Error("cannot find " + t);
    return this.$funcCaches[n] = new NativeFunction(o, e, r), this.$funcCaches[n];
  }, t.prototype.hookFunctionWithCallbacks = function(t, e) {
    var r = Module.findExportByName(null, t);
    if (null === r) throw Error("cannot find " + t);
    var n = {
      get: function(e, r, n) {
        return "name" === r ? t : e[r];
      }
    }, o = {};
    "onEnter" in e && (o.onEnter = function(t) {
      e.onEnter.call(new Proxy(this, n), t);
    }), "onLeave" in e && (o.onLeave = function(t) {
      e.onLeave.call(new Proxy(this, n), t);
    });
    var a = Interceptor.attach(r, o);
    return Log.i("Hook function: " + t + " (" + r + ")"), a;
  }, t.prototype.hookFunction = function(t, e, r, n) {
    var o = this.getExportFunction(t, e, r);
    if (null === o) throw Error("cannot find " + t);
    var a = Interceptor.attach(o, (function(a) {
      for (var i = this, s = [], c = 0; c < r.length; c++) s[c] = a[c];
      var u = new Proxy(o, {
        get: function(n, o, a) {
          switch (o) {
           case "name":
            return t;

           case "argumentTypes":
            return r;

           case "returnType":
            return e;
          }
          return o in i ? i[o] : n[o];
        },
        apply: function(t, e, r) {
          return t.apply(null, r[0]);
        }
      });
      return n.call(u, s);
    }));
    return Log.i("Hook function: " + t + " (" + o + ")"), a;
  }, t.prototype.getEventImpl = function(t, e) {
    void 0 === e && (e = !1);
    var r = new function() {
      for (var e in this.method = !0, this.thread = !1, this.stack = !1, this.args = !1, 
      this.extras = {}, t) e in this ? this[e] = t[e] : this.extras[e] = t[e];
    }, n = function(t) {
      var e = this(t), n = {};
      for (var o in r.extras) n[o] = r.extras[o];
      if (r.method && (n.method_name = this.name), r.thread && (n.thread_id = Process.getCurrentThreadId()), 
      r.args && (n.args = pretty2Json(t), n.result = pretty2Json(e)), r.stack) {
        for (var a = [], i = Thread.backtrace(this.context, Backtracer.ACCURATE), s = 0; s < i.length; s++) a.push(DebugSymbol.fromAddress(i[s]).toString());
        n.stack = a;
      }
      return send({
        event: n
      }), e;
    };
    return n.onLeave = function(t) {
      var e = {};
      for (var n in r.extras) e[n] = r.extras[n];
      if (1 == r.method && (e.method_name = this.name), !0 === r.thread && (e.thread_id = Process.getCurrentThreadId()), 
      !0 === r.args && (e.result = pretty2Json(t)), !0 === r.stack) {
        for (var o = [], a = Thread.backtrace(this.context, Backtracer.ACCURATE), i = 0; i < a.length; i++) o.push(DebugSymbol.fromAddress(a[i]).toString());
        e.stack = o;
      }
      send({
        event: e
      });
    }, n;
  }, t;
}();

exports.CHelper = t;

},{}],4:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.JavaHelper = void 0;

var t = function() {
  function t() {}
  return Object.defineProperty(t.prototype, "classClass", {
    get: function() {
      return Java.use("java.lang.Class");
    },
    enumerable: !1,
    configurable: !0
  }), Object.defineProperty(t.prototype, "stringClass", {
    get: function() {
      return Java.use("java.lang.String");
    },
    enumerable: !1,
    configurable: !0
  }), Object.defineProperty(t.prototype, "threadClass", {
    get: function() {
      return Java.use("java.lang.Thread");
    },
    enumerable: !1,
    configurable: !0
  }), Object.defineProperty(t.prototype, "throwableClass", {
    get: function() {
      return Java.use("java.lang.Throwable");
    },
    enumerable: !1,
    configurable: !0
  }), Object.defineProperty(t.prototype, "uriClass", {
    get: function() {
      return Java.use("android.net.Uri");
    },
    enumerable: !1,
    configurable: !0
  }), Object.defineProperty(t.prototype, "urlClass", {
    get: function() {
      return Java.use("java.net.URL");
    },
    enumerable: !1,
    configurable: !0
  }), Object.defineProperty(t.prototype, "mapClass", {
    get: function() {
      return Java.use("java.util.Map");
    },
    enumerable: !1,
    configurable: !0
  }), Object.defineProperty(t.prototype, "applicationContext", {
    get: function() {
      return Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
    },
    enumerable: !1,
    configurable: !0
  }), t.prototype.isArray = function(t) {
    return !!(t.hasOwnProperty("class") && t.class instanceof Object && t.class.hasOwnProperty("isArray") && t.class.isArray());
  }, t.prototype.getClassName = function(t) {
    return t.$classWrapper.__name__;
  }, t.prototype.findClass = function(t, e) {
    if (void 0 === e && (e = void 0), void 0 === e || null == e) {
      if (parseInt(Java.androidVersion) < 7) return Java.use(t);
      var r = null, a = Java.enumerateClassLoadersSync();
      for (var n in a) try {
        var o = this.findClass(t, a[n]);
        if (null != o) return o;
      } catch (t) {
        null == r && (r = t);
      }
      throw r;
    }
    var s = Java.classFactory.loader;
    try {
      return Reflect.set(Java.classFactory, "loader", e), Java.use(t);
    } finally {
      Reflect.set(Java.classFactory, "loader", s);
    }
  }, t.prototype.$fixMethod = function(t) {
    Object.defineProperties(t, {
      className: {
        configurable: !0,
        enumerable: !0,
        get: function() {
          return this.holder.$className || this.holder.__name__;
        }
      },
      name: {
        configurable: !0,
        enumerable: !0,
        get: function() {
          var t = this.returnType.className, e = this.className + "." + this.methodName, r = "";
          if (this.argumentTypes.length > 0) {
            r = this.argumentTypes[0].className;
            for (var a = 1; a < this.argumentTypes.length; a++) r = r + ", " + this.argumentTypes[a].className;
          }
          return t + " " + e + "(" + r + ")";
        }
      },
      toString: {
        value: function() {
          return this.name;
        }
      }
    });
  }, t.prototype.$hookMethod = function(t, e) {
    if (void 0 === e && (e = null), null != e) {
      var r = new Proxy(t, {
        apply: function(t, e, r) {
          var a = r[0], n = r[1];
          return t.apply(a, n);
        }
      });
      t.implementation = function() {
        return e.call(r, this, Array.prototype.slice.call(arguments));
      }, Log.i("Hook method: " + t);
    } else t.implementation = null, Log.i("Unhook method: " + t);
  }, t.prototype.hookMethod = function(t, e, r, a) {
    void 0 === a && (a = null);
    var n = e;
    if ("string" == typeof n) {
      var o = t;
      if ("string" == typeof o && (o = this.findClass(o)), n = o[n], null != r) {
        var s = r;
        for (var i in s) "string" != typeof s[i] && (s[i] = this.getClassName(s[i]));
        n = n.overload.apply(n, s);
      }
    }
    this.$fixMethod(n), this.$hookMethod(n, a);
  }, t.prototype.hookMethods = function(t, e, r) {
    void 0 === r && (r = null);
    var a = t;
    "string" == typeof a && (a = this.findClass(a));
    for (var n = a[e].overloads, o = 0; o < n.length; o++) {
      var s = n[o];
      void 0 !== s.returnType && void 0 !== s.returnType.className && (this.$fixMethod(s), 
      this.$hookMethod(s, r));
    }
  }, t.prototype.hookAllConstructors = function(t, e) {
    void 0 === e && (e = null);
    var r = t;
    "string" == typeof r && (r = this.findClass(r)), this.hookMethods(r, "$init", e);
  }, t.prototype.hookAllMethods = function(t, e) {
    void 0 === e && (e = null);
    var r = t;
    "string" == typeof r && (r = this.findClass(r));
    for (var a = [], n = r.class; null != n && "java.lang.Object" !== n.getName(); ) {
      for (var o = n.getDeclaredMethods(), s = 0; s < o.length; s++) {
        var i = o[s].getName();
        a.indexOf(i) < 0 && (a.push(i), this.hookMethods(r, i, e));
      }
      n = Java.cast(n.getSuperclass(), this.classClass);
    }
  }, t.prototype.hookClass = function(t, e) {
    void 0 === e && (e = null);
    var r = t;
    "string" == typeof r && (r = this.findClass(r)), this.hookAllConstructors(r, e), 
    this.hookAllMethods(r, e);
  }, t.prototype.callMethod = function(t, e) {
    var r = this.getStackTrace()[0].getMethodName();
    return "<init>" === r && (r = "$init"), Reflect.get(t, r).apply(t, e);
  }, t.prototype.getEventImpl = function(t) {
    var e = this, r = new function() {
      for (var e in this.method = !0, this.thread = !1, this.stack = !1, this.args = !1, 
      this.extras = {}, t) e in this ? this[e] = t[e] : this.extras[e] = t[e];
    };
    return function(t, a) {
      var n = this(t, a), o = {};
      for (var s in r.extras) o[s] = r.extras[s];
      return r.method && (o.class_name = t.$className, o.method_name = this.name, o.method_simple_name = this.methodName), 
      r.thread && (o.thread_id = Process.getCurrentThreadId(), o.thread_name = e.threadClass.currentThread().getName()), 
      r.args && (o.args = pretty2Json(a), o.result = pretty2Json(n)), r.stack && (o.stack = pretty2Json(e.getStackTrace())), 
      send({
        event: o
      }), n;
    };
  }, t.prototype.fromJavaArray = function(t, e) {
    var r = t;
    "string" == typeof r && (r = this.findClass(r));
    for (var a = [], n = Java.vm.getEnv(), o = 0; o < n.getArrayLength(e.$handle); o++) a.push(Java.cast(n.getObjectArrayElement(e.$handle, o), r));
    return a;
  }, t.prototype.getEnumValue = function(t, e) {
    var r = t;
    "string" == typeof r && (r = this.findClass(r));
    var a = r.class.getEnumConstants();
    a instanceof Array || (a = this.fromJavaArray(r, a));
    for (var n = 0; n < a.length; n++) if (a[n].toString() === e) return a[n];
    throw new Error("Name of " + e + " does not match " + r);
  }, t.prototype.getStackTrace = function() {
    for (var t = [], e = this.throwableClass.$new().getStackTrace(), r = 0; r < e.length; r++) t.push(e[r]);
    return t;
  }, t.prototype.$makeStackObject = function(t) {
    void 0 === t && (t = void 0), void 0 === t && (t = this.getStackTrace());
    for (var e = "Stack: ", r = 0; r < t.length; r++) e += "\n    at " + pretty2String(t[r]);
    return {
      stack: e
    };
  }, t.prototype.printStack = function() {
    var t = this.getStackTrace();
    Log.i(this.$makeStackObject(t));
  }, t.prototype.$makeArgsObject = function(t, e) {
    for (var r = "Arguments: ", a = 0; a < t.length; a++) r += "\n    Arguments[" + a + "]: " + pretty2String(t[a]);
    return void 0 !== e && (r += "\n    Return: " + pretty2String(e)), {
      arguments: r
    };
  }, t.prototype.printArguments = function(t, e) {
    Log.i(this.$makeArgsObject(t, e));
  }, t;
}();

exports.JavaHelper = t;

},{}],5:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.ObjCHelper = void 0;

var t = function() {
  function t() {}
  return t.prototype.$fixMethod = function(t, e) {
    var n = e.origImplementation || e.implementation, r = t.toString(), o = ObjC.selectorAsString(e.selector), i = ObjC.classes.NSThread.hasOwnProperty(o);
    Object.defineProperties(e, {
      className: {
        configurable: !0,
        enumerable: !0,
        get: function() {
          return r;
        }
      },
      methodName: {
        configurable: !0,
        enumerable: !0,
        get: function() {
          return o;
        }
      },
      name: {
        configurable: !0,
        enumerable: !0,
        get: function() {
          return (i ? "+" : "-") + "[" + r + " " + o + "]";
        }
      },
      origImplementation: {
        configurable: !0,
        enumerable: !0,
        get: function() {
          return n;
        }
      },
      toString: {
        value: function() {
          return this.name;
        }
      }
    });
  }, t.prototype.$hookMethod = function(t, e) {
    void 0 === e && (e = null), null != e ? (t.implementation = ObjC.implement(t, (function() {
      var n = this, r = Array.prototype.slice.call(arguments), o = r.shift(), i = r.shift(), a = new Proxy(t, {
        get: function(t, e, r) {
          return e in n ? n[e] : t[e];
        },
        apply: function(t, e, n) {
          var r = n[0], o = n[1];
          return t.origImplementation.apply(null, [].concat(r, i, o));
        }
      });
      return e.call(a, o, r);
    })), Log.i("Hook method: " + t)) : (t.implementation = t.origImplementation, Log.i("Unhook method: " + pretty2String(t)));
  }, t.prototype.hookMethod = function(t, e, n) {
    void 0 === n && (n = null);
    var r = t;
    if ("string" == typeof r && (r = ObjC.classes[r]), void 0 === r) throw Error('cannot find class "' + t + '"');
    var o = e;
    if ("string" == typeof o && (o = r[o]), void 0 === o) throw Error('cannot find method "' + e + '" in class "' + r + '"');
    this.$fixMethod(r, o), this.$hookMethod(o, n);
  }, t.prototype.hookMethods = function(t, e, n) {
    void 0 === n && (n = null);
    var r = t;
    if ("string" == typeof r && (r = ObjC.classes[r]), void 0 === r) throw Error('cannot find class "' + t + '"');
    for (var o = r.$ownMethods.length, i = 0; i < o; i++) {
      var a = r.$ownMethods[i];
      if (a.indexOf(e) >= 0) {
        var s = r[a];
        this.$fixMethod(r, s), this.$hookMethod(s, n);
      }
    }
  }, t.prototype.getEventImpl = function(t) {
    var e = this, n = new function() {
      for (var e in this.method = !0, this.thread = !1, this.stack = !1, this.args = !1, 
      this.extras = {}, t) e in this ? this[e] = t[e] : this.extras[e] = t[e];
    };
    return function(t, r) {
      var o = this(t, r), i = {};
      for (var a in n.extras) i[a] = n.extras[a];
      if (n.method && (i.class_name = new ObjC.Object(t).$className, i.method_name = this.name, 
      i.method_simple_name = this.methodName), n.thread && (i.thread_id = Process.getCurrentThreadId(), 
      i.thread_name = ObjC.classes.NSThread.currentThread().name().toString()), n.args) {
        for (var s = [], c = 0; c < r.length; c++) s.push(e.convert2ObjcObject(r[c]));
        i.args = pretty2Json(s), i.result = pretty2Json(e.convert2ObjcObject(o));
      }
      if (n.stack) {
        var h = [], l = Thread.backtrace(this.context, Backtracer.ACCURATE);
        for (c = 0; c < l.length; c++) h.push(DebugSymbol.fromAddress(l[c]).toString());
        i.stack = h;
      }
      return send({
        event: i
      }), o;
    };
  }, t.prototype.convert2ObjcObject = function(t) {
    return t instanceof NativePointer || "object" == typeof t && t.hasOwnProperty("handle") ? new ObjC.Object(t) : t;
  }, t;
}();

exports.ObjCHelper = t;

},{}]},{},[1])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJpbmRleC50cyIsImxpYi9hbmRyb2lkLnRzIiwibGliL2MudHMiLCJsaWIvamF2YS50cyIsImxpYi9vYmpjLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOzs7Ozs7O0FDS0EsSUFBQSxJQUFBO0VBQUEsU0FBQTtJQUVJLEtBQUEsUUFBUSxHQUNSLEtBQUEsT0FBTyxHQUNQLEtBQUEsVUFBVSxHQUNWLEtBQUEsUUFBUSxHQUNBLEtBQUEsU0FBUyxLQUFLOztFQWtDMUIsT0FoQ0ksT0FBQSxlQUFJLEVBQUEsV0FBQSxTQUFLO1NBQVQ7TUFDSSxPQUFPLEtBQUs7Ozs7TUFHaEIsRUFBQSxVQUFBLFdBQUEsU0FBUztJQUNMLEtBQUssU0FBUyxHQUNkLEtBQUssRUFBRSxvQkFBb0I7S0FHL0IsRUFBQSxVQUFBLElBQUEsU0FBRSxHQUFXO1NBQUEsTUFBQSxNQUFBLElBQUEsT0FDTCxLQUFLLFVBQVUsS0FBSyxTQUNwQixLQUFLO01BQUUsS0FBSztRQUFFLE9BQU87UUFBUyxLQUFLO1FBQUssU0FBUzs7O0tBSXpELEVBQUEsVUFBQSxJQUFBLFNBQUUsR0FBVztTQUFBLE1BQUEsTUFBQSxJQUFBLE9BQ0wsS0FBSyxVQUFVLEtBQUssUUFDcEIsS0FBSztNQUFFLEtBQUs7UUFBRSxPQUFPO1FBQVEsS0FBSztRQUFLLFNBQVM7OztLQUl4RCxFQUFBLFVBQUEsSUFBQSxTQUFFLEdBQVc7U0FBQSxNQUFBLE1BQUEsSUFBQSxPQUNMLEtBQUssVUFBVSxLQUFLLFdBQ3BCLEtBQUs7TUFBRSxLQUFLO1FBQUUsT0FBTztRQUFXLEtBQUs7UUFBSyxTQUFTOzs7S0FJM0QsRUFBQSxVQUFBLElBQUEsU0FBRSxHQUFXO1NBQUEsTUFBQSxNQUFBLElBQUEsT0FDTCxLQUFLLFVBQVUsS0FBSyxTQUNwQixLQUFLO01BQUUsS0FBSztRQUFFLE9BQU87UUFBUyxLQUFLO1FBQUssU0FBUzs7O0tBRzdEO0NB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QUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ25OQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSIsImZpbGUiOiJnZW5lcmF0ZWQuanMiLCJzb3VyY2VSb290IjoiIn0=
