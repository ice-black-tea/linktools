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
      var o = n[t];
      try {
        (0, eval)(o.source);
      } catch (e) {
        throw new Error("Unable to load ".concat(o.filename, ": ").concat(e.stack));
      }
    }
  }, e;
}(), t = new r;

rpc.exports = {
  loadScripts: t.load.bind(t)
};

var n = require("./lib/java"), o = require("./lib/android"), i = require("./lib/objc"), l = new e, a = new n.JavaHelper, u = new o.AndroidHelper, s = new i.ObjCHelper;

Object.defineProperties(globalThis, {
  Log: {
    enumerable: !0,
    value: l
  },
  JavaHelper: {
    enumerable: !0,
    value: a
  },
  AndroidHelper: {
    enumerable: !0,
    value: u
  },
  ObjCHelper: {
    enumerable: !0,
    value: s
  },
  ignoreError: {
    enumerable: !1,
    value: function(e, r) {
      void 0 === r && (r = void 0);
      try {
        return e();
      } catch (e) {
        return l.d("Catch ignored error. " + e), r;
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
      if (Array.isArray(e) || a.isArray(e)) {
        for (var r = [], t = 0; t < e.length; t++) r.push(pretty2Json(e[t]));
        return r;
      }
      return ignoreError((function() {
        return e.toString();
      }), void 0);
    }
  }
});

},{"./lib/android":2,"./lib/java":3,"./lib/objc":4}],2:[function(require,module,exports){
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
        get: function(t, e, r) {
          return t[e];
        },
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
    var e = this, r = !0, a = !1, n = !1, o = !1, s = {};
    for (var i in t) "thread" == i ? r = t[i] : "thread" == i ? a = t[i] : "stack" == i ? n = t[i] : "args" == i ? o = t[i] : s[i] = t[i];
    return function(t, i) {
      var l = this(t, i), u = {};
      for (var c in s) u[c] = s[c];
      return 1 == r && (u.class_name = t.$className, u.method_name = this.name, u.method_simple_name = this.methodName), 
      !0 === a && (u.thread_id = Process.getCurrentThreadId(), u.thread_name = e.threadClass.currentThread().getName()), 
      !0 === o && (u.args = pretty2Json(i), u.result = pretty2Json(l)), !0 === n && (u.stack = pretty2Json(e.getStackTrace())), 
      send({
        event: u
      }), l;
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

},{}],4:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.ObjCHelper = void 0;

var e = function() {
  function e() {}
  return e.prototype.$fixMethod = function(e, t) {
    var n = e.toString(), r = ObjC.selectorAsString(t.selector), o = ObjC.classes.NSThread.hasOwnProperty(r);
    Object.defineProperties(t, {
      className: {
        configurable: !0,
        enumerable: !0,
        get: function() {
          return n;
        }
      },
      methodName: {
        configurable: !0,
        enumerable: !0,
        get: function() {
          return r;
        }
      },
      name: {
        configurable: !0,
        enumerable: !0,
        get: function() {
          return (o ? "+" : "-") + "[" + n + " " + r + "]";
        }
      },
      toString: {
        value: function() {
          return this.name;
        }
      }
    });
  }, e.prototype.$hookMethod = function(e, t) {
    if (void 0 === t && (t = null), null != t) {
      var n = e.implementation;
      e.implementation = ObjC.implement(e, (function() {
        var r = this, o = Array.prototype.slice.call(arguments), a = o.shift(), i = o.shift(), c = new Proxy(e, {
          get: function(e, t, n) {
            return "context" == t ? r.context : e[t];
          },
          apply: function(e, t, r) {
            var o = r[0], a = r[1];
            return n.apply(null, [].concat(o, i, a));
          }
        });
        return t.call(c, a, o);
      })), Log.i("Hook method: " + e);
    } else e.implementation = null, Log.i("Unhook method: " + pretty2String(e));
  }, e.prototype.hookMethod = function(e, t, n) {
    void 0 === n && (n = null);
    var r = e;
    if ("string" == typeof r && (r = ObjC.classes[r]), void 0 === r) throw Error('cannot find class "' + e + '"');
    var o = t;
    if ("string" == typeof o && (o = r[o]), void 0 === o) throw Error('cannot find method "' + t + '" in class "' + r + '"');
    this.$fixMethod(r, o), this.$hookMethod(o, n);
  }, e.prototype.getEventImpl = function(e) {
    var t = this, n = !0, r = !1, o = !1, a = !1, i = {};
    for (var c in e) "thread" == c ? n = e[c] : "thread" == c ? r = e[c] : "stack" == c ? o = e[c] : "args" == c ? a = e[c] : i[c] = e[c];
    return function(e, c) {
      var s = this(e, c), l = {};
      for (var u in i) l[u] = i[u];
      if (1 == n && (l.class_name = new ObjC.Object(e).$className, l.method_name = this.name, 
      l.method_simple_name = this.methodName), !0 === r) {
        var h = ObjC.classes.NSThread.currentThread();
        l.thread_name = h.name().toString();
      }
      if (!0 === a) {
        for (var f = [], p = 0; p < c.length; p++) f.push(t.convert2ObjcObject(c[p]));
        l.args = pretty2Json(f), l.result = pretty2Json(t.convert2ObjcObject(s));
      }
      if (!0 === o) {
        var m = [], d = Thread.backtrace(this.context, Backtracer.ACCURATE);
        for (p = 0; p < d.length; p++) m.push(DebugSymbol.fromAddress(d[p]));
        l.stack = m;
      }
      return send({
        event: l
      }), s;
    };
  }, e.prototype.convert2ObjcObject = function(e) {
    return e instanceof NativePointer || "object" == typeof e && e.hasOwnProperty("handle") ? new ObjC.Object(e) : e;
  }, e;
}();

exports.ObjCHelper = e;

},{}]},{},[1])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJpbmRleC50cyIsImxpYi9hbmRyb2lkLnRzIiwibGliL2phdmEudHMiLCJsaWIvb2JqYy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7Ozs7OztBQ0tBLElBQUEsSUFBQTtFQUFBLFNBQUE7SUFFSSxLQUFBLFFBQVEsR0FDUixLQUFBLE9BQU8sR0FDUCxLQUFBLFVBQVUsR0FDVixLQUFBLFFBQVEsR0FDQSxLQUFBLFNBQVMsS0FBSzs7RUFrQzFCLE9BaENJLE9BQUEsZUFBSSxFQUFBLFdBQUEsU0FBSztTQUFUO01BQ0ksT0FBTyxLQUFLOzs7O01BR2hCLEVBQUEsVUFBQSxXQUFBLFNBQVM7SUFDTCxLQUFLLFNBQVMsR0FDZCxLQUFLLEVBQUUsb0JBQW9CO0tBRy9CLEVBQUEsVUFBQSxJQUFBLFNBQUUsR0FBVztTQUFBLE1BQUEsTUFBQSxJQUFBLE9BQ0wsS0FBSyxVQUFVLEtBQUssU0FDcEIsS0FBSztNQUFFLEtBQUs7UUFBRSxPQUFPO1FBQVMsS0FBSztRQUFLLFNBQVM7OztLQUl6RCxFQUFBLFVBQUEsSUFBQSxTQUFFLEdBQVc7U0FBQSxNQUFBLE1BQUEsSUFBQSxPQUNMLEtBQUssVUFBVSxLQUFLLFFBQ3BCLEtBQUs7TUFBRSxLQUFLO1FBQUUsT0FBTztRQUFRLEtBQUs7UUFBSyxTQUFTOzs7S0FJeEQsRUFBQSxVQUFBLElBQUEsU0FBRSxHQUFXO1NBQUEsTUFBQSxNQUFBLElBQUEsT0FDTCxLQUFLLFVBQVUsS0FBSyxXQUNwQixLQUFLO01BQUUsS0FBSztRQUFFLE9BQU87UUFBVyxLQUFLO1FBQUssU0FBUzs7O0tBSTNELEVBQUEsVUFBQSxJQUFBLFNBQUUsR0FBVztTQUFBLE1BQUEsTUFBQSxJQUFBLE9BQ0wsS0FBSyxVQUFVLEtBQUssU0FDcEIsS0FBSztNQUFFLEtBQUs7UUFBRSxPQUFPO1FBQVMsS0FBSztRQUFLLFNBQVM7OztLQUc3RDtDQXhDQSxJQXdEQSxJQUFBO0VBQUEsU0FBQTtFQWtCQSxPQWhCSSxFQUFBLFVBQUEsT0FBQSxTQUFLLEdBQW1CO0lBQ3BCLE9BQU8saUJBQWlCLFlBQVk7TUFDaEMsWUFBWTtRQUNSLGFBQVk7UUFDWixPQUFPOzs7SUFJZixLQUFxQixJQUFBLElBQUEsR0FBQSxJQUFBLEdBQUEsSUFBQSxFQUFBLFFBQUEsS0FBUztNQUF6QixJQUFNLElBQU0sRUFBQTtNQUNiO1NBQ0ksR0FBSSxNQUFNLEVBQU87UUFDbkIsT0FBTztRQUNMLE1BQU0sSUFBSSxNQUFNLGtCQUFBLE9BQWtCLEVBQU8sVUFBUSxNQUFBLE9BQUssRUFBRTs7O0tBSXhFO0NBbEJBLElBb0JNLElBQVMsSUFBSTs7QUFFbkIsSUFBSSxVQUFVO0VBQ1YsYUFBYSxFQUFPLEtBQUssS0FBSzs7O0FBUWxDLElBQUEsSUFBQSxRQUFBLGVBQ0EsSUFBQSxRQUFBLGtCQUNBLElBQUEsUUFBQSxlQUVNLElBQU0sSUFBSSxHQUNWLElBQWEsSUFBSSxFQUFBLFlBQ2pCLElBQWdCLElBQUksRUFBQSxlQUNwQixJQUFhLElBQUksRUFBQTs7QUFjdkIsT0FBTyxpQkFBaUIsWUFBWTtFQUNoQyxLQUFLO0lBQ0QsYUFBWTtJQUNaLE9BQU87O0VBRVgsWUFBWTtJQUNSLGFBQVk7SUFDWixPQUFPOztFQUVYLGVBQWU7SUFDWCxhQUFZO0lBQ1osT0FBTzs7RUFFWCxZQUFZO0lBQ1IsYUFBWTtJQUNaLE9BQU87O0VBRVgsYUFBYTtJQUNULGFBQVk7SUFDWixPQUFPLFNBQWEsR0FBYTtXQUFBLE1BQUEsTUFBQSxTQUFBO01BQzdCO1FBQ0ksT0FBTztRQUNULE9BQU87UUFFTCxPQURBLEVBQUksRUFBRSwwQkFBMEIsSUFDekI7Ozs7RUFJbkIsZUFBZTtJQUNYLGFBQVk7SUFDWixPQUFPLFNBQVU7TUFFYixRQURBLElBQU0sWUFBWSxlQUNHLFNBR2QsS0FBSyxVQUFVLEtBRlg7OztFQUtuQixhQUFhO0lBQ1QsYUFBWTtJQUNaLE9BQU8sU0FBVTtNQUNiLE1BQU0sYUFBZSxTQUNqQixPQUFPO01BRVgsSUFBSSxNQUFNLFFBQVEsTUFBUSxFQUFXLFFBQVEsSUFBTTtRQUUvQyxLQURBLElBQUksSUFBUyxJQUNKLElBQUksR0FBRyxJQUFJLEVBQUksUUFBUSxLQUM1QixFQUFPLEtBQUssWUFBWSxFQUFJO1FBRWhDLE9BQU87O01BRVgsT0FBTyxhQUFZO1FBQU0sT0FBQSxFQUFJO2VBQVk7Ozs7OztBQ3BLckQ7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOzs7Ozs7OztBQ3ZSQSxJQUFBLElBQUE7RUFBQSxTQUFBO0VBaWNBLE9BL2JJLE9BQUEsZUFBSSxFQUFBLFdBQUEsY0FBVTtTQUFkO01BQ0ksT0FBTyxLQUFLLElBQUk7Ozs7TUFH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
