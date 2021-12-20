(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
});

var e = require("./lib/base"), r = require("./lib/java"), l = require("./lib/objc"), i = require("./lib/android");

globalThis.Log = e.Log, globalThis.JavaHelper = new r.JavaHelper, globalThis.ObjCHelper = new l.ObjCHelper, 
globalThis.AndroidHelper = new i.AndroidHelper;

},{"./lib/android":2,"./lib/base":3,"./lib/java":4,"./lib/objc":5}],2:[function(require,module,exports){
"use strict";

var n = this && this.__extends || function() {
  var n = function(e, t) {
    return n = Object.setPrototypeOf || {
      __proto__: []
    } instanceof Array && function(n, e) {
      n.__proto__ = e;
    } || function(n, e) {
      for (var t in e) Object.prototype.hasOwnProperty.call(e, t) && (n[t] = e[t]);
    }, n(e, t);
  };
  return function(e, t) {
    if ("function" != typeof t && null !== t) throw new TypeError("Class extends value " + String(t) + " is not a constructor or null");
    function r() {
      this.constructor = e;
    }
    n(e, t), e.prototype = null === t ? Object.create(t) : (r.prototype = t.prototype, 
    new r);
  };
}();

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.AndroidHelper = void 0;

var e = require("./base"), t = function(t) {
  function r() {
    return t.call(this) || this;
  }
  return n(r, t), r.prototype.setWebviewDebuggingEnabled = function() {
    var n = globalThis.JavaHelper;
    e.Log.i("======================================================\r\nAndroid Enable Webview Debugging                      \r\n======================================================"), 
    Java.perform((function() {
      n.hookMethods("android.webkit.WebView", "loadUrl", (function(n, t) {
        return e.Log.d("setWebContentsDebuggingEnabled: " + n), n.setWebContentsDebuggingEnabled(!0), 
        this.apply(n, t);
      }));
    }));
    try {
      n.hookMethods("com.uc.webview.export.WebView", "loadUrl", (function(n, t) {
        return e.Log.d("setWebContentsDebuggingEnabled: " + n), n.setWebContentsDebuggingEnabled(!0), 
        this.apply(n, t);
      }));
    } catch (n) {
      e.Log.d("Hook com.uc.webview.export.WebView.loadUrl error: " + n, "[-]");
    }
  }, r.prototype.bypassSslPinningLite = function() {
    var n = globalThis.JavaHelper;
    e.Log.i("======================================================\r\nAndroid Bypass ssl pinning                           \r\n======================================================"), 
    Java.perform((function() {
      try {
        var t = Java.use("java.util.Arrays");
        n.hookMethods("com.android.org.conscrypt.TrustManagerImpl", "checkServerTrusted", (function(n, r) {
          if (e.Log.d("Bypassing TrustManagerImpl checkServerTrusted"), "pointer" == this.returnType.type && "java.util.List" == this.returnType.className) return t.asList(r[0]);
        }));
      } catch (n) {
        e.Log.d("Hook com.android.org.conscrypt.TrustManagerImpl.checkTrusted error: " + n, "[-]");
      }
      try {
        n.hookMethods("com.google.android.gms.org.conscrypt.Platform", "checkServerTrusted", (function(n, t) {
          e.Log.d("Bypassing Platform checkServerTrusted {1}");
        }));
      } catch (n) {
        e.Log.d("Hook com.google.android.gms.org.conscrypt.Platform.checkServerTrusted error: " + n, "[-]");
      }
      try {
        n.hookMethods("com.android.org.conscrypt.Platform", "checkServerTrusted", (function(n, t) {
          e.Log.d("Bypassing Platform checkServerTrusted {2}");
        }));
      } catch (n) {
        e.Log.d("Hook com.android.org.conscrypt.Platform.checkServerTrusted error: " + n, "[-]");
      }
    }));
  }, r.prototype.bypassSslPinning = function() {
    var n = globalThis.JavaHelper;
    e.Log.i("======================================================\r\nAndroid Bypass for various Certificate Pinning methods\r\n======================================================"), 
    Java.perform((function() {
      var t = [ Java.registerClass({
        name: "xxx.xxx.xxx.TrustManager",
        implements: [ Java.use("javax.net.ssl.X509TrustManager") ],
        methods: {
          checkClientTrusted: function(n, e) {},
          checkServerTrusted: function(n, e) {},
          getAcceptedIssuers: function() {
            return [];
          }
        }
      }).$new() ];
      try {
        n.hookMethod("javax.net.ssl.SSLContext", "init", [ "[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom" ], (function(n, r) {
          return e.Log.d("Bypassing Trustmanager (Android < 7) pinner"), r[1] = t, this.apply(n, r);
        }));
      } catch (n) {
        e.Log.d("TrustManager (Android < 7) pinner not found", "[-]");
      }
      try {
        n.hookMethods("okhttp3.CertificatePinner", "check", (function(n, t) {
          e.Log.d("Bypassing OkHTTPv3 {1}: " + t[0]);
        }));
      } catch (n) {
        e.Log.d("OkHTTPv3 {1} pinner not found: " + n, "[-]");
      }
      try {
        n.hookMethod("okhttp3.CertificatePinner", "check$okhttp", [ "java.lang.String", "kotlin.jvm.functions.Function0" ], (function(n, t) {
          e.Log.d("Bypassing OkHTTPv3 {4}: " + t[0]);
        }));
      } catch (n) {
        e.Log.d("OkHTTPv3 {4} pinner not found: " + n, "[-]");
      }
      try {
        n.hookMethods("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier", "verify", (function(n, t) {
          return e.Log.d("Bypassing Trustkit {1}: " + t[0]), !0;
        }));
      } catch (n) {
        e.Log.d("Trustkit {1} pinner not found: " + n, "[-]");
      }
      try {
        n.hookMethods("com.datatheorem.android.trustkit.pinning.PinningTrustManager", "checkServerTrusted", (function(n, t) {
          e.Log.d("Bypassing Trustkit {3}");
        }));
      } catch (n) {
        e.Log.d("Trustkit {3} pinner not found: " + n, "[-]");
      }
      try {
        var r = Java.use("java.util.ArrayList");
        n.hookMethods("com.android.org.conscrypt.TrustManagerImpl", "checkTrustedRecursive", (function(n, t) {
          return e.Log.d("Bypassing TrustManagerImpl (Android > 7) checkTrustedRecursive check: " + t[3]), 
          r.$new();
        }));
      } catch (n) {
        e.Log.d("TrustManagerImpl (Android > 7) checkTrustedRecursive check not found: " + n, "[-]");
      }
      try {
        n.hookMethods("com.android.org.conscrypt.TrustManagerImpl", "verifyChain", (function(n, t) {
          return e.Log.d("Bypassing TrustManagerImpl (Android > 7) verifyChain check: " + t[2]), 
          t[0];
        }));
      } catch (n) {
        e.Log.d("TrustManagerImpl (Android > 7) verifyChain check not found: " + n, "[-]");
      }
      try {
        n.hookMethods("appcelerator.https.PinningTrustManager", "checkServerTrusted", (function() {
          e.Log.d("Bypassing Appcelerator PinningTrustManager");
        }));
      } catch (n) {
        e.Log.d("Appcelerator PinningTrustManager pinner not found: " + n, "[-]");
      }
      try {
        n.hookMethods("io.fabric.sdk.android.services.network.PinningTrustManager", "checkServerTrusted", (function() {
          e.Log.d("Bypassing Fabric PinningTrustManager");
        }));
      } catch (n) {
        e.Log.d("Fabric PinningTrustManager pinner not found: " + n, "[-]");
      }
      try {
        n.hookMethods("com.android.org.conscrypt.OpenSSLSocketImpl", "verifyCertificateChain", (function() {
          e.Log.d("Bypassing OpenSSLSocketImpl Conscrypt {1}");
        }));
      } catch (n) {
        e.Log.d("OpenSSLSocketImpl Conscrypt {1} pinner not found: " + n, "[-]");
      }
      try {
        n.hookMethods("com.android.org.conscrypt.OpenSSLEngineSocketImpl", "verifyCertificateChain", (function(n, t) {
          e.Log.d("Bypassing OpenSSLEngineSocketImpl Conscrypt: " + (t.length >= 2 ? t[1] : null));
        }));
      } catch (n) {
        e.Log.d("OpenSSLEngineSocketImpl Conscrypt pinner not found: " + n, "[-]");
      }
      try {
        n.hookMethods("org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl", "verifyCertificateChain", (function(n, t) {
          e.Log.d("Bypassing OpenSSLSocketImpl Apache Harmony");
        }));
      } catch (n) {
        e.Log.d("OpenSSLSocketImpl Apache Harmony pinner not found: " + n, "[-]");
      }
      try {
        n.hookMethod("nl.xservices.plugins.sslCertificateChecker", "execute", [ "java.lang.String", "org.json.JSONArray", "org.apache.cordova.CallbackContext" ], (function(n, t) {
          return e.Log.d("Bypassing PhoneGap sslCertificateChecker: " + t[0]), !0;
        }));
      } catch (n) {
        e.Log.d("PhoneGap sslCertificateChecker pinner not found: " + n, "[-]");
      }
      try {
        var o = Java.use("com.worklight.wlclient.api.WLClient");
        n.hookMethods(o.getInstance(), "pinTrustedCertificatePublicKey", (function(n, t) {
          e.Log.d("Bypassing IBM MobileFirst pinTrustedCertificatePublicKey {1}: " + t[0]);
        }));
      } catch (n) {
        e.Log.d("IBM MobileFirst pinTrustedCertificatePublicKey {1} pinner not found: " + n, "[-]");
      }
      try {
        n.hookMethods("com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning", "verify", (function(n, t) {
          e.Log.d("Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {1}: " + t[0]);
        }));
      } catch (n) {
        e.Log.d("IBM WorkLight HostNameVerifierWithCertificatePinning {1} pinner not found: " + n, "[-]");
      }
      try {
        n.hookMethod("com.android.org.conscrypt.CertPinManager", "checkChainPinning", [ "java.lang.String", "java.util.List" ], (function(n, t) {
          return e.Log.d("Bypassing Conscrypt CertPinManager: " + t[0]), !0;
        }));
      } catch (n) {
        e.Log.d("Conscrypt CertPinManager pinner not found: " + n, "[-]");
      }
      try {
        n.hookMethod("com.android.org.conscrypt.CertPinManager", "isChainValid", [ "java.lang.String", "java.util.List" ], (function(n, t) {
          return e.Log.d("Bypassing Conscrypt CertPinManager (Legacy): " + t[0]), !0;
        }));
      } catch (n) {
        e.Log.d("Conscrypt CertPinManager (Legacy) pinner not found: " + n, "[-]");
      }
      try {
        n.hookMethod("com.commonsware.cwac.netsecurity.conscrypt.CertPinManager", "isChainValid", [ "java.lang.String", "java.util.List" ], (function(n, t) {
          return e.Log.d("Bypassing CWAC-Netsecurity CertPinManager: " + t[0]), !0;
        }));
      } catch (n) {
        e.Log.d("CWAC-Netsecurity CertPinManager pinner not found: " + n, "[-]");
      }
      try {
        n.hookMethod("com.worklight.androidgap.plugin.WLCertificatePinningPlugin", "execute", [ "java.lang.String", "org.json.JSONArray", "org.apache.cordova.CallbackContext" ], (function(n, t) {
          return e.Log.d("Bypassing Worklight Androidgap WLCertificatePinningPlugin: " + t[0]), 
          !0;
        }));
      } catch (n) {
        e.Log.d("Worklight Androidgap WLCertificatePinningPlugin pinner not found: " + n, "[-]");
      }
      try {
        n.hookMethods("io.netty.handler.ssl.util.FingerprintTrustManagerFactory", "checkTrusted", (function(n, t) {
          e.Log.d("Bypassing Netty FingerprintTrustManagerFactory");
        }));
      } catch (n) {
        e.Log.d("Netty FingerprintTrustManagerFactory pinner not found: " + n, "[-]");
      }
      try {
        n.hookMethods("com.squareup.okhttp.CertificatePinner", "check", (function(n, t) {
          e.Log.d("Bypassing Squareup CertificatePinner {1}: " + t[0]);
        }));
      } catch (n) {
        e.Log.d("Squareup CertificatePinner {1} pinner not found: " + n, "[-]");
      }
      try {
        n.hookMethods("com.squareup.okhttp.internal.tls.OkHostnameVerifier", "verify", (function(n, t) {
          return e.Log.d("Bypassing Squareup OkHostnameVerifier {1}: " + t[0]), !0;
        }));
      } catch (n) {
        e.Log.d("Squareup OkHostnameVerifier check not found: " + n, "[-]");
      }
      try {
        n.hookMethods("com.android.okhttp.internal.tls.OkHostnameVerifier", "verify", (function(n, t) {
          return e.Log.d("Bypassing android OkHostnameVerifier {2}: " + t[0]), !0;
        }));
      } catch (n) {
        e.Log.d("android OkHostnameVerifier check not found: " + n, "[-]");
      }
      try {
        n.hookMethods("okhttp3.internal.tls.OkHostnameVerifier", "verify", (function(n, t) {
          return e.Log.d("Bypassing okhttp3 OkHostnameVerifier {3}: " + t[0]), !0;
        }));
      } catch (n) {
        e.Log.d("okhttp3 OkHostnameVerifier check not found: " + n, "[-]");
      }
      try {
        n.hookMethods("android.webkit.WebViewClient", "onReceivedSslError", (function(n, t) {
          e.Log.d("Bypassing Android WebViewClient check {1}");
        }));
      } catch (n) {
        e.Log.d("Android WebViewClient {1} check not found: " + n, "[-]");
      }
      try {
        n.hookMethods("android.webkit.WebViewClient", "onReceivedError", (function(n, t) {
          e.Log.d("Bypassing Android WebViewClient check {3}");
        }));
      } catch (n) {
        e.Log.d("Android WebViewClient {3} check not found: " + n, "[-]");
      }
      try {
        n.hookMethod("org.apache.cordova.CordovaWebViewClient", "onReceivedSslError", [ "android.webkit.WebView", "android.webkit.SslErrorHandler", "android.net.http.SslError" ], (function(n, t) {
          e.Log.d("Bypassing Apache Cordova WebViewClient check"), t[3].proceed();
        }));
      } catch (n) {
        e.Log.d("Apache Cordova WebViewClient check not found: " + n, "[-]");
      }
      try {
        n.hookMethods("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier", "verify", (function(n, t) {
          e.Log.d("Bypassing Boye AbstractVerifier check: " + t[0]);
        }));
      } catch (n) {
        e.Log.d("Boye AbstractVerifier check not found: " + n, "[-]");
      }
      try {
        n.hookMethod("org.apache.http.conn.ssl.AbstractVerifier", "verify", [ "java.lang.String", "[Ljava.lang.String;", "[Ljava.lang.String;", "boolean" ], (function(n, t) {
          e.Log.d("Bypassing Apache AbstractVerifier check: " + t[0]);
        }));
      } catch (n) {
        e.Log.d("Apache AbstractVerifier check not found: " + n, "[-]");
      }
      try {
        n.hookMethod("org.chromium.net.impl.CronetEngineBuilderImpl", "enablePublicKeyPinningBypassForLocalTrustAnchors", [ "boolean" ], (function(n, t) {
          return e.Log.i("[+] Disabling Public Key pinning for local trust anchors in Chromium Cronet"), 
          t[0] = !0, this.apply(n, t);
        }));
      } catch (n) {
        e.Log.d("Chromium Cronet pinner not found: " + n, "[-]");
      }
      try {
        n.hookMethods("diefferson.http_certificate_pinning.HttpCertificatePinning", "checkConnexion", (function(n, t) {
          return e.Log.d("Bypassing Flutter HttpCertificatePinning : " + t[0]), !0;
        }));
      } catch (n) {
        e.Log.d("Flutter HttpCertificatePinning pinner not found: " + n, "[-]");
      }
      try {
        n.hookMethods("javax.net.ssl.SSLPeerUnverifiedException", "$init", (function(t, r) {
          e.Log.w("Unexpected SSLPeerUnverifiedException occurred, trying to patch it dynamically...", "[!]");
          var o = Java.use("java.lang.Thread").currentThread().getStackTrace(), i = o.findIndex((function(n) {
            return "javax.net.ssl.SSLPeerUnverifiedException" === n.getClassName();
          })), a = o[i + 1], c = a.getClassName(), s = a.getMethodName();
          return n.hookMethods(c, s, (function(n, e) {
            return void 0 === (t = this.returnType.type) || "void" == t ? void 0 : "boolean" === t || null;
            var t;
          })), this.apply(t, r);
        }));
      } catch (n) {
        e.Log.d("SSLPeerUnverifiedException not found: " + n, "[-]");
      }
    }));
  }, r;
}(e.Base);

exports.AndroidHelper = t;

},{"./base":3}],3:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.Base = exports.Log = void 0;

var e = function() {
  function e() {}
  return e.setLevel = function(n) {
    e.$level = n, e.d("Set log level: " + n);
  }, e.d = function(n, o) {
    void 0 === o && (o = null), e.$level <= e.debug && send({
      log: {
        level: "debug",
        tag: o,
        message: n
      }
    });
  }, e.i = function(n, o) {
    void 0 === o && (o = null), e.$level <= e.info && send({
      log: {
        level: "info",
        tag: o,
        message: n
      }
    });
  }, e.w = function(n, o) {
    void 0 === o && (o = null), e.$level <= e.warning && send({
      log: {
        level: "warning",
        tag: o,
        message: n
      }
    });
  }, e.e = function(n, o) {
    void 0 === o && (o = null), e.$level <= e.error && send({
      log: {
        level: "error",
        tag: o,
        message: n
      }
    });
  }, e.debug = 1, e.info = 2, e.warning = 3, e.error = 4, e.$level = e.info, e;
}();

exports.Log = e;

var n = function() {
  function e() {}
  return e.prototype.addMethod = function(e, n) {
    this[e + "_$_$_" + n.length] = n, this[e] = function() {
      var n = e + "_$_$_" + arguments.length;
      if (this.hasOwnProperty(n)) return this[n].apply(this, arguments);
      throw new Error("Argument count of " + arguments.length + " does not match " + e);
    };
  }, e.prototype.ignoreError = function(e, n) {
    void 0 === n && (n = void 0);
    try {
      return e();
    } catch (e) {
      return n;
    }
  }, e;
}();

exports.Base = n;

},{}],4:[function(require,module,exports){
"use strict";

var t = this && this.__extends || function() {
  var t = function(e, r) {
    return t = Object.setPrototypeOf || {
      __proto__: []
    } instanceof Array && function(t, e) {
      t.__proto__ = e;
    } || function(t, e) {
      for (var r in e) Object.prototype.hasOwnProperty.call(e, r) && (t[r] = e[r]);
    }, t(e, r);
  };
  return function(e, r) {
    if ("function" != typeof r && null !== r) throw new TypeError("Class extends value " + String(r) + " is not a constructor or null");
    function o() {
      this.constructor = e;
    }
    t(e, r), e.prototype = null === r ? Object.create(r) : (o.prototype = r.prototype, 
    new o);
  };
}();

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.JavaHelper = void 0;

var e = require("./base"), r = function(r) {
  function o() {
    return null !== r && r.apply(this, arguments) || this;
  }
  return t(o, r), Object.defineProperty(o.prototype, "javaClass", {
    get: function() {
      return Java.use("java.lang.Class");
    },
    enumerable: !1,
    configurable: !0
  }), Object.defineProperty(o.prototype, "javaString", {
    get: function() {
      return Java.use("java.lang.String");
    },
    enumerable: !1,
    configurable: !0
  }), Object.defineProperty(o.prototype, "javaThrowable", {
    get: function() {
      return Java.use("java.lang.Throwable");
    },
    enumerable: !1,
    configurable: !0
  }), o.prototype.getClassName = function(t) {
    return t.$classWrapper.__name__;
  }, o.prototype.findClass = function(t, e) {
    if (void 0 === e && (e = void 0), void 0 === e) {
      var r = null, o = Java.enumerateClassLoadersSync();
      for (var n in o) try {
        var a = this.findClass(t, o[n]);
        if (null != a) return a;
      } catch (t) {
        null == r && (r = t);
      }
      throw r;
    }
    var i = Java.classFactory.loader;
    try {
      return Reflect.set(Java.classFactory, "loader", e), Java.use(t);
    } finally {
      Reflect.set(Java.classFactory, "loader", i);
    }
  }, o.prototype.$fixMethod = function(t) {
    t.toString = function() {
      var t = this.returnType.className, e = (this.holder.$className || this.holder.__name__) + "." + this.methodName, r = "";
      if (this.argumentTypes.length > 0) {
        r = this.argumentTypes[0].className;
        for (var o = 1; o < this.argumentTypes.length; o++) r = r + ", " + this.argumentTypes[o].className;
      }
      return t + " " + e + "(" + r + ")";
    };
  }, o.prototype.$hookMethod = function(t, r) {
    void 0 === r && (r = null), null != r ? (t.implementation = function() {
      return r.call(t, this, arguments);
    }, this.$fixMethod(t), e.Log.i("Hook method: " + t)) : (t.implementation = null, 
    this.$fixMethod(t), e.Log.i("Unhook method: " + t));
  }, o.prototype.hookMethod = function(t, e, r, o) {
    void 0 === o && (o = null);
    var n = e;
    if ("string" == typeof n) {
      var a = t;
      if ("string" == typeof a && (a = this.findClass(a)), n = a[n], null != r) {
        var i = r;
        for (var s in i) "string" != typeof i[s] && (i[s] = this.getClassName(i[s]));
        n = n.overload.apply(n, i);
      }
    }
    this.$hookMethod(n, o);
  }, o.prototype.hookMethods = function(t, e, r) {
    void 0 === r && (r = null);
    var o = t;
    "string" == typeof o && (o = this.findClass(o));
    for (var n = o[e].overloads, a = 0; a < n.length; a++) void 0 !== n[a].returnType && void 0 !== n[a].returnType.className && this.$hookMethod(n[a], r);
  }, o.prototype.hookClass = function(t, e) {
    void 0 === e && (e = null);
    var r = t;
    "string" == typeof r && (r = this.findClass(r)), this.hookMethods(r, "$init", e);
    for (var o = [], n = r.class; null != n && "java.lang.Object" !== n.getName(); ) {
      for (var a = n.getDeclaredMethods(), i = 0; i < a.length; i++) {
        var s = a[i].getName();
        o.indexOf(s) < 0 && (o.push(s), this.hookMethods(r, s, e));
      }
      n = Java.cast(n.getSuperclass(), this.javaClass);
    }
  }, o.prototype.callMethod = function(t, e) {
    var r = this.getStackTrace()[0].getMethodName();
    return "<init>" === r && (r = "$init"), Reflect.get(t, r).apply(t, e);
  }, o.prototype.getHookImpl = function(t) {
    var r = this, o = t.printStack || !1, n = t.printArgs || !1;
    return function(t, a) {
      var i = {}, s = this.apply(t, a);
      return !1 !== o && (i = Object.assign(i, r.$makeStackObject(this))), !1 !== n && (i = Object.assign(i, r.$makeArgsObject(a, s, this))), 
      0 !== Object.keys(i).length && e.Log.i(i), s;
    };
  }, o.prototype.fromJavaArray = function(t, e) {
    var r = t;
    "string" == typeof r && (r = this.findClass(r));
    for (var o = [], n = Java.vm.getEnv(), a = 0; a < n.getArrayLength(e.$handle); a++) o.push(Java.cast(n.getObjectArrayElement(e.$handle, a), r));
    return o;
  }, o.prototype.getEnumValue = function(t, e) {
    var r = t;
    "string" == typeof r && (r = this.findClass(r));
    var o = r.class.getEnumConstants();
    o instanceof Array || (o = this.fromJavaArray(r, o));
    for (var n = 0; n < o.length; n++) if (o[n].toString() === e) return o[n];
    throw new Error("Name of " + e + " does not match " + r);
  }, o.prototype.getStackTrace = function() {
    return this.javaThrowable.$new().getStackTrace();
  }, o.prototype.$makeStackObject = function(t, e) {
    void 0 === e && (e = void 0), void 0 === e && (e = this.getStackTrace());
    for (var r = "Stack: " + t, o = 0; o < e.length; o++) r += "\n    at " + this.toString(e[o]);
    return {
      stack: r
    };
  }, o.prototype.printStack = function(t) {
    void 0 === t && (t = void 0);
    var r = this.getStackTrace();
    null == t && (t = r[0]), e.Log.i(this.$makeStackObject(t, r));
  }, o.prototype.toString = function(t) {
    if (void 0 === t || null == t || !(t instanceof Object)) return t;
    if (Array.isArray(t)) {
      for (var e = [], r = 0; r < t.length; r++) e.push(this.toString(t[r]));
      return "[" + e.toString() + "]";
    }
    return this.ignoreError((function() {
      return t.toString();
    }), void 0);
  }, o.prototype.$makeArgsObject = function(t, e, r) {
    for (var o = "Arguments: " + r, n = 0; n < t.length; n++) o += "\n    Arguments[" + n + "]: " + this.toString(t[n]);
    return void 0 !== e && (o += "\n    Return: " + this.toString(e)), {
      arguments: o
    };
  }, o.prototype.printArguments = function(t, r, o) {
    void 0 === o && (o = void 0), void 0 === o && (o = this.getStackTrace()[0]), e.Log.i(this.$makeArgsObject(t, r, o));
  }, o;
}(e.Base);

exports.JavaHelper = r;

},{"./base":3}],5:[function(require,module,exports){
"use strict";

var t = this && this.__extends || function() {
  var t = function(e, r) {
    return t = Object.setPrototypeOf || {
      __proto__: []
    } instanceof Array && function(t, e) {
      t.__proto__ = e;
    } || function(t, e) {
      for (var r in e) Object.prototype.hasOwnProperty.call(e, r) && (t[r] = e[r]);
    }, t(e, r);
  };
  return function(e, r) {
    if ("function" != typeof r && null !== r) throw new TypeError("Class extends value " + String(r) + " is not a constructor or null");
    function o() {
      this.constructor = e;
    }
    t(e, r), e.prototype = null === r ? Object.create(r) : (o.prototype = r.prototype, 
    new o);
  };
}();

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.ObjCHelper = void 0;

var e = require("./base"), r = function(e) {
  function r() {
    return e.call(this) || this;
  }
  return t(r, e), r;
}(e.Base);

exports.ObjCHelper = r;

},{"./base":3}]},{},[1])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJpbmRleC50cyIsImxpYi9hbmRyb2lkLnRzIiwibGliL2Jhc2UudHMiLCJsaWIvamF2YS50cyIsImxpYi9vYmpjLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOzs7Ozs7O0FDQUEsSUFBQSxJQUFBLFFBQUEsZUFDQSxJQUFBLFFBQUEsZUFDQSxJQUFBLFFBQUEsZUFDQSxJQUFBLFFBQUE7O0FBRUEsV0FBVyxNQUFNLEVBQUEsS0FDakIsV0FBVyxhQUFhLElBQUksRUFBQSxZQUM1QixXQUFXLGFBQWEsSUFBSSxFQUFBO0FBQzVCLFdBQVcsZ0JBQWdCLElBQUksRUFBQTs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7QUNSL0IsSUFBQSxJQUFBLFFBQUEsV0FHQSxJQUFBLFNBQUE7RUFFSSxTQUFBO1dBQ0ksRUFBQSxLQUFBLFNBQU87O0VBeWlCZixPQTVpQm1DLEVBQUEsR0FBQSxJQU8vQixFQUFBLFVBQUEsNkJBQUE7SUFDSSxJQUFNLElBQXlCLFdBQVc7SUFFMUMsRUFBQSxJQUFJLEVBQ0E7SUFLSixLQUFLLFNBQVE7TUFDVCxFQUFXLFlBQVksMEJBQTBCLFlBQVcsU0FBVSxHQUFLO1FBR3ZFLE9BRkEsRUFBQSxJQUFJLEVBQUUscUNBQXFDLElBQzNDLEVBQUksZ0NBQStCO1FBQzVCLEtBQUssTUFBTSxHQUFLOzs7SUFJL0I7TUFDSSxFQUFXLFlBQVksaUNBQWlDLFlBQVcsU0FBVSxHQUFLO1FBRzlFLE9BRkEsRUFBQSxJQUFJLEVBQUUscUNBQXFDLElBQzNDLEVBQUksZ0NBQStCO1FBQzVCLEtBQUssTUFBTSxHQUFLOztNQUU3QixPQUFPO01BQ0wsRUFBQSxJQUFJLEVBQUUsdURBQXVELEdBQUs7O0tBSzFFLEVBQUEsVUFBQSx1QkFBQTtJQUVJLElBQU0sSUFBeUIsV0FBVztJQUUxQyxFQUFBLElBQUksRUFDQTtJQUtKLEtBQUssU0FBUTtNQUNUO1FBQ0ksSUFBTSxJ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
