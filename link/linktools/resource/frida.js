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
  }), t.prototype.getApplicationContext = function() {
    var t = Java.use("android.app.ActivityThread"), e = Java.use("android.content.Context");
    return Java.cast(t.currentApplication().getApplicationContext(), e);
  }, t.prototype.getClassName = function(t) {
    return t.$classWrapper.__name__;
  }, t.prototype.findClass = function(t, e) {
    if (void 0 === e && (e = void 0), void 0 === e || null == e) {
      if (parseInt(Java.androidVersion) < 7) return Java.use(t);
      var r = null, o = Java.enumerateClassLoadersSync();
      for (var n in o) try {
        var a = this.findClass(t, o[n]);
        if (null != a) return a;
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
      toJson: {
        configurable: !0,
        enumerable: !0,
        value: function() {
          var t = this.returnType.className, e = this.className + "." + this.methodName, r = "";
          if (this.argumentTypes.length > 0) {
            r = this.argumentTypes[0].className;
            for (var o = 1; o < this.argumentTypes.length; o++) r = r + ", " + this.argumentTypes[o].className;
          }
          return t + " " + e + "(" + r + ")";
        }
      }
    });
  }, t.prototype.$hookMethod = function(t, e) {
    void 0 === e && (e = null), null != e ? (t.implementation = function() {
      return e.call(t, this, arguments);
    }, this.$fixMethod(t), Log.i("Hook method: " + this.toString(t))) : (t.implementation = null, 
    this.$fixMethod(t), Log.i("Unhook method: " + this.toString(t)));
  }, t.prototype.hookMethod = function(t, e, r, o) {
    void 0 === o && (o = null);
    var n = e;
    if ("string" == typeof n) {
      var a = t;
      if ("string" == typeof a && (a = this.findClass(a)), n = a[n], null != r) {
        var s = r;
        for (var i in s) "string" != typeof s[i] && (s[i] = this.getClassName(s[i]));
        n = n.overload.apply(n, s);
      }
    }
    this.$hookMethod(n, o);
  }, t.prototype.hookMethods = function(t, e, r) {
    void 0 === r && (r = null);
    var o = t;
    "string" == typeof o && (o = this.findClass(o));
    for (var n = o[e].overloads, a = 0; a < n.length; a++) void 0 !== n[a].returnType && void 0 !== n[a].returnType.className && this.$hookMethod(n[a], r);
  }, t.prototype.hookAllConstructors = function(t, e) {
    void 0 === e && (e = null);
    var r = t;
    "string" == typeof r && (r = this.findClass(r)), this.hookMethods(r, "$init", e);
  }, t.prototype.hookAllMethods = function(t, e) {
    void 0 === e && (e = null);
    var r = t;
    "string" == typeof r && (r = this.findClass(r));
    for (var o = [], n = r.class; null != n && "java.lang.Object" !== n.getName(); ) {
      for (var a = n.getDeclaredMethods(), s = 0; s < a.length; s++) {
        var i = a[s].getName();
        o.indexOf(i) < 0 && (o.push(i), this.hookMethods(r, i, e));
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
    var e = this, r = t.printStack || !1, o = t.printArgs || !1;
    return function(t, n) {
      var a = {}, s = this.apply(t, n);
      return !1 !== r && (a = Object.assign(a, e.$makeStackObject(this))), !1 !== o && (a = Object.assign(a, e.$makeArgsObject(n, s, this))), 
      0 !== Object.keys(a).length && Log.i(a), s;
    };
  }, t.prototype.getEventImpl = function(t) {
    var e = this, r = !1, o = !1, n = !1, a = {};
    for (var s in t) "thread" == s ? r = t[s] : "stack" == s ? o = t[s] : "args" == s ? n = t[s] : a[s] = t[s];
    return function(t, s) {
      var i = this.apply(t, s), l = {
        method_simple_name: this.methodName,
        method_name: e.toString(this)
      };
      for (var u in !0 === r && (l.thread_id = Process.getCurrentThreadId(), l.thread_name = e.threadClass.currentThread().getName()), 
      !0 === n && (l.object = e.toJson(t), l.args = e.toJson(Array.prototype.slice.call(s)), 
      l.result = e.toJson(i)), !0 === o && (l.stack = e.toJson(e.getStackTrace())), a) l[u] = a[u];
      return send({
        event: l
      }), i;
    };
  }, t.prototype.fromJavaArray = function(t, e) {
    var r = t;
    "string" == typeof r && (r = this.findClass(r));
    for (var o = [], n = Java.vm.getEnv(), a = 0; a < n.getArrayLength(e.$handle); a++) o.push(Java.cast(n.getObjectArrayElement(e.$handle, a), r));
    return o;
  }, t.prototype.getEnumValue = function(t, e) {
    var r = t;
    "string" == typeof r && (r = this.findClass(r));
    var o = r.class.getEnumConstants();
    o instanceof Array || (o = this.fromJavaArray(r, o));
    for (var n = 0; n < o.length; n++) if (o[n].toString() === e) return o[n];
    throw new Error("Name of " + e + " does not match " + r);
  }, t.prototype.getStackTrace = function() {
    for (var t = [], e = this.throwableClass.$new().getStackTrace(), r = 0; r < e.length; r++) t.push(e[r]);
    return t;
  }, t.prototype.$makeStackObject = function(t, e) {
    void 0 === e && (e = void 0), void 0 === e && (e = this.getStackTrace());
    for (var r = "Stack: " + t, o = 0; o < e.length; o++) r += "\n    at " + this.toString(e[o]);
    return {
      stack: r
    };
  }, t.prototype.printStack = function(t) {
    void 0 === t && (t = void 0);
    var e = this.getStackTrace();
    null == t && (t = e[0]), Log.i(this.$makeStackObject(t, e));
  }, t.prototype.toString = function(t) {
    return (t = this.toJson(t)) instanceof Object ? JSON.stringify(t) : t;
  }, t.prototype.toJson = function(t) {
    if (!(t instanceof Object)) return t;
    if (Array.isArray(t)) {
      for (var e = [], r = 0; r < t.length; r++) e.push(this.toJson(t[r]));
      return e;
    }
    if (t.hasOwnProperty("class") && t.class instanceof Object) {
      if (t.class.hasOwnProperty("isArray") && t.class.isArray()) {
        for (e = [], r = 0; r < t.length; r++) e.push(this.toJson(t[r]));
        return e;
      }
      if (t.class.hasOwnProperty("toString")) return ignoreError((function() {
        return t.toString();
      }), void 0);
    }
    return t.hasOwnProperty("toJson") ? ignoreError((function() {
      return t.toJson();
    }), void 0) : t;
  }, t.prototype.$makeArgsObject = function(t, e, r) {
    for (var o = "Arguments: " + r, n = 0; n < t.length; n++) o += "\n    Arguments[" + n + "]: " + this.toString(t[n]);
    return void 0 !== e && (o += "\n    Return: " + this.toString(e)), {
      arguments: o
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJpbmRleC50cyIsImxpYi9hbmRyb2lkLnRzIiwibGliL2phdmEudHMiLCJsaWIvb2JqYy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7Ozs7OztBQ0FBLElBQUEsSUFBQSxRQUFBLGVBQ0EsSUFBQSxRQUFBLGtCQUNBLElBQUEsUUFBQSxlQXNCQSxJQUFBO0VBQUEsU0FBQTtFQWtCQSxPQWhCSSxFQUFBLFVBQUEsT0FBQSxTQUFLLEdBQW1CO0lBQ3BCLE9BQU8saUJBQWlCLFlBQVk7TUFDaEMsWUFBWTtRQUNSLGFBQVk7UUFDWixPQUFPOzs7SUFJZixLQUFxQixJQUFBLElBQUEsR0FBQSxJQUFBLEdBQUEsSUFBQSxFQUFBLFFBQUEsS0FBUztNQUF6QixJQUFNLElBQU0sRUFBQTtNQUNiO1NBQ0ksR0FBSSxNQUFNLEVBQU87UUFDbkIsT0FBTztRQUNMLE1BQU0sSUFBSSxNQUFNLGtCQUFBLE9BQWtCLEVBQU8sVUFBUSxNQUFBLE9BQUssRUFBRTs7O0tBSXhFO0NBbEJBLElBb0JNLElBQVMsSUFBSTs7QUFFbkIsSUFBSSxVQUFVO0VBQ1YsYUFBYSxFQUFPLEtBQUssS0FBSzs7O0FBSWxDLElBQUEsSUFBQTtFQUFBLFNBQUE7SUFFSSxLQUFBLFFBQVEsR0FDUixLQUFBLE9BQU8sR0FDUCxLQUFBLFVBQVUsR0FDVixLQUFBLFFBQVEsR0FDQSxLQUFBLFNBQVMsS0FBSzs7RUFrQzFCLE9BaENJLE9BQUEsZUFBSSxFQUFBLFdBQUEsU0FBSztTQUFUO01BQ0ksT0FBTyxLQUFLOzs7O01BR2hCLEVBQUEsVUFBQSxXQUFBLFNBQVM7SUFDTCxLQUFLLFNBQVMsR0FDZCxLQUFLLEVBQUUsb0JBQW9CO0tBRy9CLEVBQUEsVUFBQSxJQUFBLFNBQUUsR0FBVztTQUFBLE1BQUEsTUFBQSxJQUFBLE9BQ0wsS0FBSyxVQUFVLEtBQUssU0FDcEIsS0FBSztNQUFFLEtBQUs7UUFBRSxPQUFPO1FBQVMsS0FBSztRQUFLLFNBQVM7OztLQUl6RCxFQUFBLFVBQUEsSUFBQSxTQUFFLEdBQVc7U0FBQSxNQUFBLE1BQUEsSUFBQSxPQUNMLEtBQUssVUFBVSxLQUFLLFFBQ3BCLEtBQUs7TUFBRSxLQUFLO1FBQUUsT0FBTztRQUFRLEtBQUs7UUFBSyxTQUFTOzs7S0FJeEQsRUFBQSxVQUFBLElBQUEsU0FBRSxHQUFXO1NBQUEsTUFBQSxNQUFBLElBQUEsT0FDTCxLQUFLLFVBQVUsS0FBSyxXQUNwQixLQUFLO01BQUUsS0FBSztRQUFFLE9BQU87UUFBVyxLQUFLO1FBQUssU0FBUzs7O0tBSTNELEVBQUEsVUFBQSxJQUFBLFNBQUUsR0FBVztTQUFBLE1BQUEsTUFBQSxJQUFBLE9BQ0wsS0FBSyxVQUFVLEtBQUssU0FDcEIsS0FBSztNQUFFLEtBQUs7UUFBRSxPQUFPO1FBQVMsS0FBSztRQUFLLFNBQVM7OztLQUc3RDtDQXhDQTs7QUEyQ0EsT0FBTyxpQkFBaUIsWUFBWTtFQUNoQyxLQUFLO0lBQ0QsYUFBWTtJQUNaLE9BQU8sSUFBSTs7RUFFZixZQUFZO0lBQ1IsYUFBWTtJQUNaLE9BQU8sSUFBSSxFQUFBOztFQUVmLGVBQWU7SUFDWCxhQUFZO0lBQ1osT0FBTyxJQUFJLEVBQUE7O0VBRWYsWUFBWTtJQUNSLGFBQVk7SUFDWixPQUFPLElBQUksRUFBQTs7RUFFZixhQUFhO0lBQ1QsYUFBWTtJQUNaLE9BQU8sU0FBYSxHQUFhO1dBQUEsTUFBQSxNQUFBLFNBQUE7TUFDN0I7UUFDSSxPQUFPO1FBQ1QsT0FBQTtRQUNFLE9BQU87Ozs7Ozs7QUNySHZCO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFD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
