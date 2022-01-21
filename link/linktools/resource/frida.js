(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
});

var e = require("./lib/java"), r = require("./lib/android"), t = require("./lib/objc"), l = function() {
  function e() {}
  return e.prototype.load = function(e, r) {
    Object.defineProperties(globalThis, {
      parameters: {
        enumerable: !0,
        value: r
      }
    });
    for (var t = 0, l = e; t < l.length; t++) {
      var n = l[t];
      try {
        (0, eval)(n.source);
      } catch (e) {
        throw new Error("Unable to load ".concat(n.filename, ": ").concat(e.stack));
      }
    }
  }, e;
}(), n = new l;

rpc.exports = {
  loadScripts: n.load.bind(n)
};

var o = function() {
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
}();

Object.defineProperties(globalThis, {
  Log: {
    enumerable: !0,
    value: new o
  },
  JavaHelper: {
    enumerable: !0,
    value: new e.JavaHelper
  },
  AndroidHelper: {
    enumerable: !0,
    value: new r.AndroidHelper
  },
  ObjCHelper: {
    enumerable: !0,
    value: new t.ObjCHelper
  },
  ignoreError: {
    enumerable: !1,
    value: function(e, r) {
      void 0 === r && (r = void 0);
      try {
        return e();
      } catch (e) {
        return r;
      }
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
  }), t.prototype.getClassName = function(t) {
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
      pretty2Json: {
        configurable: !0,
        enumerable: !0,
        value: function() {
          var t = this.returnType.className, e = this.className + "." + this.methodName, r = "";
          if (this.argumentTypes.length > 0) {
            r = this.argumentTypes[0].className;
            for (var a = 1; a < this.argumentTypes.length; a++) r = r + ", " + this.argumentTypes[a].className;
          }
          return t + " " + e + "(" + r + ")";
        }
      }
    });
  }, t.prototype.$hookMethod = function(t, e) {
    void 0 === e && (e = null), null != e ? (t.implementation = function() {
      return e.call(t, this, arguments);
    }, this.$fixMethod(t), Log.i("Hook method: " + this.pretty(t))) : (t.implementation = null, 
    this.$fixMethod(t), Log.i("Unhook method: " + this.pretty(t)));
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
    this.$hookMethod(n, a);
  }, t.prototype.hookMethods = function(t, e, r) {
    void 0 === r && (r = null);
    var a = t;
    "string" == typeof a && (a = this.findClass(a));
    for (var n = a[e].overloads, o = 0; o < n.length; o++) void 0 !== n[o].returnType && void 0 !== n[o].returnType.className && this.$hookMethod(n[o], r);
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
  }, t.prototype.getHookImpl = function(t) {
    var e = this, r = t.printStack || !1, a = t.printArgs || !1;
    return function(t, n) {
      var o = {}, s = this.apply(t, n);
      return !1 !== r && (o = Object.assign(o, e.$makeStackObject(this))), !1 !== a && (o = Object.assign(o, e.$makeArgsObject(n, s, this))), 
      0 !== Object.keys(o).length && Log.i(o), s;
    };
  }, t.prototype.getEventImpl = function(t) {
    var e = this, r = !1, a = !1, n = !1, o = {};
    for (var s in t) "thread" == s ? r = t[s] : "stack" == s ? a = t[s] : "args" == s ? n = t[s] : o[s] = t[s];
    return function(t, s) {
      var i = this.apply(t, s), l = {};
      for (var u in o) l[u] = o[u];
      return l.method_name = e.pretty(this), l.method_simple_name = this.methodName, !0 === r && (l.thread_id = Process.getCurrentThreadId(), 
      l.thread_name = e.threadClass.currentThread().getName()), !0 === n && (l.object = t.$className, 
      l.args = e.pretty2Json(Array.prototype.slice.call(s)), l.result = e.pretty2Json(i)), 
      !0 === a && (l.stack = e.pretty2Json(e.getStackTrace())), send({
        event: l
      }), i;
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
  }, t.prototype.$makeStackObject = function(t, e) {
    void 0 === e && (e = void 0), void 0 === e && (e = this.getStackTrace());
    for (var r = "Stack: " + t, a = 0; a < e.length; a++) r += "\n    at " + this.pretty(e[a]);
    return {
      stack: r
    };
  }, t.prototype.printStack = function(t) {
    void 0 === t && (t = void 0);
    var e = this.getStackTrace();
    null == t && (t = e[0]), Log.i(this.$makeStackObject(t, e));
  }, t.prototype.pretty = function(t) {
    return (t = this.pretty2Json(t)) instanceof Object ? JSON.stringify(t) : t;
  }, t.prototype.pretty2Json = function(t) {
    if (!(t instanceof Object)) return t;
    if (Array.isArray(t)) {
      for (var e = [], r = 0; r < t.length; r++) e.push(this.pretty2Json(t[r]));
      return e;
    }
    if (t.hasOwnProperty("class") && t.class instanceof Object) {
      if (t.class.hasOwnProperty("isArray") && t.class.isArray()) {
        for (e = [], r = 0; r < t.length; r++) e.push(this.pretty2Json(t[r]));
        return e;
      }
      if (t.class.hasOwnProperty("toString")) return ignoreError((function() {
        return t.toString();
      }), void 0);
    }
    return t.hasOwnProperty("pretty2Json") ? ignoreError((function() {
      return t.pretty2Json();
    }), void 0) : t;
  }, t.prototype.$makeArgsObject = function(t, e, r) {
    for (var a = "Arguments: " + r, n = 0; n < t.length; n++) a += "\n    Arguments[" + n + "]: " + this.pretty(t[n]);
    return void 0 !== e && (a += "\n    Return: " + this.pretty(e)), {
      arguments: a
    };
  }, t.prototype.printArguments = function(t, e, r) {
    void 0 === r && (r = void 0), void 0 === r && (r = this.getStackTrace()[0]), Log.i(this.$makeArgsObject(t, e, r));
  }, t;
}();

exports.JavaHelper = t;

},{}],4:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.ObjCHelper = void 0;

var e = function() {};

exports.ObjCHelper = e;

},{}]},{},[1])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJpbmRleC50cyIsImxpYi9hbmRyb2lkLnRzIiwibGliL2phdmEudHMiLCJsaWIvb2JqYy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7Ozs7OztBQ0FBLElBQUEsSUFBQSxRQUFBLGVBQ0EsSUFBQSxRQUFBLGtCQUNBLElBQUEsUUFBQSxlQXNCQSxJQUFBO0VBQUEsU0FBQTtFQWtCQSxPQWhCSSxFQUFBLFVBQUEsT0FBQSxTQUFLLEdBQW1CO0lBQ3BCLE9BQU8saUJBQWlCLFlBQVk7TUFDaEMsWUFBWTtRQUNSLGFBQVk7UUFDWixPQUFPOzs7SUFJZixLQUFxQixJQUFBLElBQUEsR0FBQSxJQUFBLEdBQUEsSUFBQSxFQUFBLFFBQUEsS0FBUztNQUF6QixJQUFNLElBQU0sRUFBQTtNQUNiO1NBQ0ksR0FBSSxNQUFNLEVBQU87UUFDbkIsT0FBTztRQUNMLE1BQU0sSUFBSSxNQUFNLGtCQUFBLE9BQWtCLEVBQU8sVUFBUSxNQUFBLE9BQUssRUFBRTs7O0tBSXhFO0NBbEJBLElBb0JNLElBQVMsSUFBSTs7QUFFbkIsSUFBSSxVQUFVO0VBQ1YsYUFBYSxFQUFPLEtBQUssS0FBSzs7O0FBSWxDLElBQUEsSUFBQTtFQUFBLFNBQUE7SUFFSSxLQUFBLFFBQVEsR0FDUixLQUFBLE9BQU8sR0FDUCxLQUFBLFVBQVUsR0FDVixLQUFBLFFBQVEsR0FDQSxLQUFBLFNBQVMsS0FBSzs7RUFrQzFCLE9BaENJLE9BQUEsZUFBSSxFQUFBLFdBQUEsU0FBSztTQUFUO01BQ0ksT0FBTyxLQUFLOzs7O01BR2hCLEVBQUEsVUFBQSxXQUFBLFNBQVM7SUFDTCxLQUFLLFNBQVMsR0FDZCxLQUFLLEVBQUUsb0JBQW9CO0tBRy9CLEVBQUEsVUFBQSxJQUFBLFNBQUUsR0FBVztTQUFBLE1BQUEsTUFBQSxJQUFBLE9BQ0wsS0FBSyxVQUFVLEtBQUssU0FDcEIsS0FBSztNQUFFLEtBQUs7UUFBRSxPQUFPO1FB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QTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUMzTkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EiLCJmaWxlIjoiZ2VuZXJhdGVkLmpzIiwic291cmNlUm9vdCI6IiJ9
