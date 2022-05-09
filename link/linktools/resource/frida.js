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
        configurable: !0,
        enumerable: !0,
        value: r
      }
    });
    for (var t = 0, n = e; t < n.length; t++) {
      var o = n[t];
      try {
        (0, eval)(o.source);
      } catch (e) {
        var i = e.hasOwnProperty("stack") ? e.stack : e;
        throw new Error("Unable to load ".concat(o.filename, ": ").concat(i));
      }
    }
  }, e;
}(), t = new r;

rpc.exports = {
  loadScripts: t.load.bind(t)
};

var n = require("./lib/c"), o = require("./lib/java"), i = require("./lib/android"), l = require("./lib/objc"), a = new e, u = new n.CHelper, s = new o.JavaHelper, v = new i.AndroidHelper, c = new l.ObjCHelper;

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
    value: v
  },
  ObjCHelper: {
    enumerable: !0,
    value: c
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
  parseBoolean: {
    enumerable: !1,
    value: function(e, r) {
      if (void 0 === r && (r = void 0), "boolean" == typeof e) return e;
      if ("string" == typeof e) {
        var t = e.toLowerCase();
        if ("true" === t) return !0;
        if ("false" === t) return !1;
      }
      return r;
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
      var e = Java.use("android.webkit.WebView");
      Java.scheduleOnMainThread((function() {
        return ignoreError((function() {
          return e.setWebContentsDebuggingEnabled(!0);
        }), void 0);
      })), JavaHelper.hookMethods(e, "setWebContentsDebuggingEnabled", (function(e, n) {
        return Log.d("android.webkit.WebView.setWebContentsDebuggingEnabled: " + n[0]), 
        n[0] = !0, this(e, n);
      })), JavaHelper.hookMethods(e, "loadUrl", (function(n, r) {
        return Log.d("android.webkit.WebView.loadUrl: " + r[0]), e.setWebContentsDebuggingEnabled(!0), 
        this(n, r);
      }));
      try {
        var n = Java.use("com.uc.webview.export.WebView");
        Java.scheduleOnMainThread((function() {
          return ignoreError((function() {
            return n.setWebContentsDebuggingEnabled(!0);
          }), void 0);
        })), JavaHelper.hookMethods(n, "setWebContentsDebuggingEnabled", (function(e, n) {
          return Log.d("com.uc.webview.export.WebView.setWebContentsDebuggingEnabled: " + n[0]), 
          n[0] = !0, this(e, n);
        })), JavaHelper.hookMethods(n, "loadUrl", (function(e, r) {
          return Log.d("com.uc.webview.export.WebView.loadUrl: " + r[0]), n.setWebContentsDebuggingEnabled(!0), 
          this(e, r);
        }));
      } catch (e) {
        Log.d("Hook com.uc.webview.export.WebView.setWebContentsDebuggingEnabled error: " + e, "[-]");
      }
    }));
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
          return Log.d("Bypassing Trustmanager (Android < 7) pinner"), r[1] = e, this(n, r);
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
          n[0] = !0, this(e, n);
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
          })), this(e, n);
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
        configurable: !0,
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJpbmRleC50cyIsImxpYi9hbmRyb2lkLnRzIiwibGliL2MudHMiLCJsaWIvamF2YS50cyIsImxpYi9vYmpjLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOzs7Ozs7O0FDS0EsSUFBQSxJQUFBO0VBQUEsU0FBQTtJQUVJLEtBQUEsUUFBUSxHQUNSLEtBQUEsT0FBTyxHQUNQLEtBQUEsVUFBVSxHQUNWLEtBQUEsUUFBUSxHQUNBLEtBQUEsU0FBUyxLQUFLOztFQWtDMUIsT0FoQ0ksT0FBQSxlQUFJLEVBQUEsV0FBQSxTQUFLO1NBQVQ7TUFDSSxPQUFPLEtBQUs7Ozs7TUFHaEIsRUFBQSxVQUFBLFdBQUEsU0FBUztJQUNMLEtBQUssU0FBUyxHQUNkLEtBQUssRUFBRSxvQkFBb0I7S0FHL0IsRUFBQSxVQUFBLElBQUEsU0FBRSxHQUFXO1NBQUEsTUFBQSxNQUFBLElBQUEsT0FDTCxLQUFLLFVBQVUsS0FBSyxTQUNwQixLQUFLO01BQUUsS0FBSztRQUFFLE9BQU87UUFBUyxLQUFLO1FBQUssU0FBUzs7O0tBSXpELEVBQUEsVUFBQSxJQUFBLFNBQUUsR0FBVztTQUFBLE1BQUEsTUFBQSxJQUFBLE9BQ0wsS0FBSyxVQUFVLEtBQUssUUFDcEIsS0FBSztNQUFFLEtBQUs7UUFBRSxPQUFPO1FBQVEsS0FBSztRQUFLLFNBQVM7OztLQUl4RCxFQUFBLFVBQUEsSUFBQSxTQUFFLEdBQVc7U0FBQSxNQUFBLE1BQUEsSUFBQSxPQUNMLEtBQUssVUFBVSxLQUFLLFdBQ3BCLEtBQUs7TUFBRSxLQUFLO1FBQUUsT0FBTztRQUFXLEtBQUs7UUFBSyxTQUFTOzs7S0FJM0QsRUFBQSxVQUFBLElBQUEsU0FBRSxHQUFXO1NBQUEsTUFBQSxNQUFBLElBQUEsT0FDTCxLQUFLLFVBQVUsS0FBSyxTQUNwQixLQUFLO01BQUUsS0FBSztRQUFFLE9BQU87UUFBUyxLQUFLO1FBQUssU0FBUzs7O0tBRzdEO0NB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QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDalVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOzs7Ozs7OztBQ3RFQSxJQUFBLElBQUE7RUFBQSxTQUFBO0VBNGJBLE9BMWJJLE9BQUEsZUFBSSxFQUFBLFdBQUEsY0FBVTtTQUFkO01BQ0ksT0FBTyxLQUFLLElBQUk7Ozs7TUFHcEIsT0FBQSxlQUFJ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
