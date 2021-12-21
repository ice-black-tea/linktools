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

var e = this && this.__extends || function() {
  var e = function(n, t) {
    return e = Object.setPrototypeOf || {
      __proto__: []
    } instanceof Array && function(e, n) {
      e.__proto__ = n;
    } || function(e, n) {
      for (var t in n) Object.prototype.hasOwnProperty.call(n, t) && (e[t] = n[t]);
    }, e(n, t);
  };
  return function(n, t) {
    if ("function" != typeof t && null !== t) throw new TypeError("Class extends value " + String(t) + " is not a constructor or null");
    function r() {
      this.constructor = n;
    }
    e(n, t), n.prototype = null === t ? Object.create(t) : (r.prototype = t.prototype, 
    new r);
  };
}();

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.AndroidHelper = void 0;

var n = require("./base"), t = function(t) {
  function r() {
    return t.call(this) || this;
  }
  return e(r, t), r.prototype.setWebviewDebuggingEnabled = function() {
    var e = globalThis.JavaHelper;
    n.Log.i("======================================================\r\nAndroid Enable Webview Debugging                      \r\n======================================================"), 
    Java.perform((function() {
      e.hookMethods("android.webkit.WebView", "loadUrl", (function(e, t) {
        return n.Log.d("setWebContentsDebuggingEnabled: " + e), e.setWebContentsDebuggingEnabled(!0), 
        this.apply(e, t);
      }));
    }));
    try {
      e.hookMethods("com.uc.webview.export.WebView", "loadUrl", (function(e, t) {
        return n.Log.d("setWebContentsDebuggingEnabled: " + e), e.setWebContentsDebuggingEnabled(!0), 
        this.apply(e, t);
      }));
    } catch (e) {
      n.Log.d("Hook com.uc.webview.export.WebView.loadUrl error: " + e, "[-]");
    }
  }, r.prototype.bypassSslPinningLite = function() {
    var e = globalThis.JavaHelper;
    n.Log.i("======================================================\r\nAndroid Bypass ssl pinning                           \r\n======================================================"), 
    Java.perform((function() {
      try {
        var t = Java.use("java.util.Arrays");
        e.hookMethods("com.android.org.conscrypt.TrustManagerImpl", "checkServerTrusted", (function(e, r) {
          if (n.Log.d("Bypassing TrustManagerImpl checkServerTrusted"), "void" != this.returnType.type) return "pointer" == this.returnType.type && "java.util.List" == this.returnType.className ? t.asList(r[0]) : void 0;
        }));
      } catch (e) {
        n.Log.d("Hook com.android.org.conscrypt.TrustManagerImpl.checkTrusted error: " + e, "[-]");
      }
      try {
        e.hookMethods("com.google.android.gms.org.conscrypt.Platform", "checkServerTrusted", (function(e, t) {
          n.Log.d("Bypassing Platform checkServerTrusted {1}");
        }));
      } catch (e) {
        n.Log.d("Hook com.google.android.gms.org.conscrypt.Platform.checkServerTrusted error: " + e, "[-]");
      }
      try {
        e.hookMethods("com.android.org.conscrypt.Platform", "checkServerTrusted", (function(e, t) {
          n.Log.d("Bypassing Platform checkServerTrusted {2}");
        }));
      } catch (e) {
        n.Log.d("Hook com.android.org.conscrypt.Platform.checkServerTrusted error: " + e, "[-]");
      }
    }));
  }, r.prototype.bypassSslPinning = function() {
    var e = globalThis.JavaHelper;
    n.Log.i("======================================================\r\nAndroid Bypass for various Certificate Pinning methods\r\n======================================================"), 
    Java.perform((function() {
      var t = [ Java.registerClass({
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
        e.hookMethod("javax.net.ssl.SSLContext", "init", [ "[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom" ], (function(e, r) {
          return n.Log.d("Bypassing Trustmanager (Android < 7) pinner"), r[1] = t, this.apply(e, r);
        }));
      } catch (e) {
        n.Log.d("TrustManager (Android < 7) pinner not found", "[-]");
      }
      try {
        e.hookMethods("okhttp3.CertificatePinner", "check", (function(e, t) {
          n.Log.d("Bypassing OkHTTPv3 {1}: " + t[0]);
        }));
      } catch (e) {
        n.Log.d("OkHTTPv3 {1} pinner not found: " + e, "[-]");
      }
      try {
        e.hookMethod("okhttp3.CertificatePinner", "check$okhttp", [ "java.lang.String", "kotlin.jvm.functions.Function0" ], (function(e, t) {
          n.Log.d("Bypassing OkHTTPv3 {4}: " + t[0]);
        }));
      } catch (e) {
        n.Log.d("OkHTTPv3 {4} pinner not found: " + e, "[-]");
      }
      try {
        e.hookMethods("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier", "verify", (function(e, t) {
          return n.Log.d("Bypassing Trustkit {1}: " + t[0]), !0;
        }));
      } catch (e) {
        n.Log.d("Trustkit {1} pinner not found: " + e, "[-]");
      }
      try {
        e.hookMethods("com.datatheorem.android.trustkit.pinning.PinningTrustManager", "checkServerTrusted", (function(e, t) {
          n.Log.d("Bypassing Trustkit {3}");
        }));
      } catch (e) {
        n.Log.d("Trustkit {3} pinner not found: " + e, "[-]");
      }
      try {
        var r = Java.use("java.util.ArrayList");
        e.hookMethods("com.android.org.conscrypt.TrustManagerImpl", "checkTrustedRecursive", (function(e, t) {
          return n.Log.d("Bypassing TrustManagerImpl (Android > 7) checkTrustedRecursive check: " + t[3]), 
          r.$new();
        }));
      } catch (e) {
        n.Log.d("TrustManagerImpl (Android > 7) checkTrustedRecursive check not found: " + e, "[-]");
      }
      try {
        e.hookMethods("com.android.org.conscrypt.TrustManagerImpl", "verifyChain", (function(e, t) {
          return n.Log.d("Bypassing TrustManagerImpl (Android > 7) verifyChain check: " + t[2]), 
          t[0];
        }));
      } catch (e) {
        n.Log.d("TrustManagerImpl (Android > 7) verifyChain check not found: " + e, "[-]");
      }
      try {
        e.hookMethods("appcelerator.https.PinningTrustManager", "checkServerTrusted", (function() {
          n.Log.d("Bypassing Appcelerator PinningTrustManager");
        }));
      } catch (e) {
        n.Log.d("Appcelerator PinningTrustManager pinner not found: " + e, "[-]");
      }
      try {
        e.hookMethods("io.fabric.sdk.android.services.network.PinningTrustManager", "checkServerTrusted", (function() {
          n.Log.d("Bypassing Fabric PinningTrustManager");
        }));
      } catch (e) {
        n.Log.d("Fabric PinningTrustManager pinner not found: " + e, "[-]");
      }
      try {
        e.hookMethods("com.android.org.conscrypt.OpenSSLSocketImpl", "verifyCertificateChain", (function() {
          n.Log.d("Bypassing OpenSSLSocketImpl Conscrypt {1}");
        }));
      } catch (e) {
        n.Log.d("OpenSSLSocketImpl Conscrypt {1} pinner not found: " + e, "[-]");
      }
      try {
        e.hookMethods("com.android.org.conscrypt.OpenSSLEngineSocketImpl", "verifyCertificateChain", (function(e, t) {
          n.Log.d("Bypassing OpenSSLEngineSocketImpl Conscrypt: " + (t.length >= 2 ? t[1] : null));
        }));
      } catch (e) {
        n.Log.d("OpenSSLEngineSocketImpl Conscrypt pinner not found: " + e, "[-]");
      }
      try {
        e.hookMethods("org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl", "verifyCertificateChain", (function(e, t) {
          n.Log.d("Bypassing OpenSSLSocketImpl Apache Harmony");
        }));
      } catch (e) {
        n.Log.d("OpenSSLSocketImpl Apache Harmony pinner not found: " + e, "[-]");
      }
      try {
        e.hookMethod("nl.xservices.plugins.sslCertificateChecker", "execute", [ "java.lang.String", "org.json.JSONArray", "org.apache.cordova.CallbackContext" ], (function(e, t) {
          return n.Log.d("Bypassing PhoneGap sslCertificateChecker: " + t[0]), !0;
        }));
      } catch (e) {
        n.Log.d("PhoneGap sslCertificateChecker pinner not found: " + e, "[-]");
      }
      try {
        var o = Java.use("com.worklight.wlclient.api.WLClient");
        e.hookMethods(o.getInstance(), "pinTrustedCertificatePublicKey", (function(e, t) {
          n.Log.d("Bypassing IBM MobileFirst pinTrustedCertificatePublicKey {1}: " + t[0]);
        }));
      } catch (e) {
        n.Log.d("IBM MobileFirst pinTrustedCertificatePublicKey {1} pinner not found: " + e, "[-]");
      }
      try {
        e.hookMethods("com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning", "verify", (function(e, t) {
          n.Log.d("Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {1}: " + t[0]);
        }));
      } catch (e) {
        n.Log.d("IBM WorkLight HostNameVerifierWithCertificatePinning {1} pinner not found: " + e, "[-]");
      }
      try {
        e.hookMethod("com.android.org.conscrypt.CertPinManager", "checkChainPinning", [ "java.lang.String", "java.util.List" ], (function(e, t) {
          return n.Log.d("Bypassing Conscrypt CertPinManager: " + t[0]), !0;
        }));
      } catch (e) {
        n.Log.d("Conscrypt CertPinManager pinner not found: " + e, "[-]");
      }
      try {
        e.hookMethod("com.android.org.conscrypt.CertPinManager", "isChainValid", [ "java.lang.String", "java.util.List" ], (function(e, t) {
          return n.Log.d("Bypassing Conscrypt CertPinManager (Legacy): " + t[0]), !0;
        }));
      } catch (e) {
        n.Log.d("Conscrypt CertPinManager (Legacy) pinner not found: " + e, "[-]");
      }
      try {
        e.hookMethod("com.commonsware.cwac.netsecurity.conscrypt.CertPinManager", "isChainValid", [ "java.lang.String", "java.util.List" ], (function(e, t) {
          return n.Log.d("Bypassing CWAC-Netsecurity CertPinManager: " + t[0]), !0;
        }));
      } catch (e) {
        n.Log.d("CWAC-Netsecurity CertPinManager pinner not found: " + e, "[-]");
      }
      try {
        e.hookMethod("com.worklight.androidgap.plugin.WLCertificatePinningPlugin", "execute", [ "java.lang.String", "org.json.JSONArray", "org.apache.cordova.CallbackContext" ], (function(e, t) {
          return n.Log.d("Bypassing Worklight Androidgap WLCertificatePinningPlugin: " + t[0]), 
          !0;
        }));
      } catch (e) {
        n.Log.d("Worklight Androidgap WLCertificatePinningPlugin pinner not found: " + e, "[-]");
      }
      try {
        e.hookMethods("io.netty.handler.ssl.util.FingerprintTrustManagerFactory", "checkTrusted", (function(e, t) {
          n.Log.d("Bypassing Netty FingerprintTrustManagerFactory");
        }));
      } catch (e) {
        n.Log.d("Netty FingerprintTrustManagerFactory pinner not found: " + e, "[-]");
      }
      try {
        e.hookMethods("com.squareup.okhttp.CertificatePinner", "check", (function(e, t) {
          n.Log.d("Bypassing Squareup CertificatePinner {1}: " + t[0]);
        }));
      } catch (e) {
        n.Log.d("Squareup CertificatePinner {1} pinner not found: " + e, "[-]");
      }
      try {
        e.hookMethods("com.squareup.okhttp.internal.tls.OkHostnameVerifier", "verify", (function(e, t) {
          return n.Log.d("Bypassing Squareup OkHostnameVerifier {1}: " + t[0]), !0;
        }));
      } catch (e) {
        n.Log.d("Squareup OkHostnameVerifier check not found: " + e, "[-]");
      }
      try {
        e.hookMethods("com.android.okhttp.internal.tls.OkHostnameVerifier", "verify", (function(e, t) {
          return n.Log.d("Bypassing android OkHostnameVerifier {2}: " + t[0]), !0;
        }));
      } catch (e) {
        n.Log.d("android OkHostnameVerifier check not found: " + e, "[-]");
      }
      try {
        e.hookMethods("okhttp3.internal.tls.OkHostnameVerifier", "verify", (function(e, t) {
          return n.Log.d("Bypassing okhttp3 OkHostnameVerifier {3}: " + t[0]), !0;
        }));
      } catch (e) {
        n.Log.d("okhttp3 OkHostnameVerifier check not found: " + e, "[-]");
      }
      try {
        e.hookMethods("android.webkit.WebViewClient", "onReceivedSslError", (function(e, t) {
          n.Log.d("Bypassing Android WebViewClient check {1}");
        }));
      } catch (e) {
        n.Log.d("Android WebViewClient {1} check not found: " + e, "[-]");
      }
      try {
        e.hookMethods("android.webkit.WebViewClient", "onReceivedError", (function(e, t) {
          n.Log.d("Bypassing Android WebViewClient check {3}");
        }));
      } catch (e) {
        n.Log.d("Android WebViewClient {3} check not found: " + e, "[-]");
      }
      try {
        e.hookMethod("org.apache.cordova.CordovaWebViewClient", "onReceivedSslError", [ "android.webkit.WebView", "android.webkit.SslErrorHandler", "android.net.http.SslError" ], (function(e, t) {
          n.Log.d("Bypassing Apache Cordova WebViewClient check"), t[3].proceed();
        }));
      } catch (e) {
        n.Log.d("Apache Cordova WebViewClient check not found: " + e, "[-]");
      }
      try {
        e.hookMethods("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier", "verify", (function(e, t) {
          n.Log.d("Bypassing Boye AbstractVerifier check: " + t[0]);
        }));
      } catch (e) {
        n.Log.d("Boye AbstractVerifier check not found: " + e, "[-]");
      }
      try {
        e.hookMethod("org.apache.http.conn.ssl.AbstractVerifier", "verify", [ "java.lang.String", "[Ljava.lang.String;", "[Ljava.lang.String;", "boolean" ], (function(e, t) {
          n.Log.d("Bypassing Apache AbstractVerifier check: " + t[0]);
        }));
      } catch (e) {
        n.Log.d("Apache AbstractVerifier check not found: " + e, "[-]");
      }
      try {
        e.hookMethod("org.chromium.net.impl.CronetEngineBuilderImpl", "enablePublicKeyPinningBypassForLocalTrustAnchors", [ "boolean" ], (function(e, t) {
          return n.Log.i("[+] Disabling Public Key pinning for local trust anchors in Chromium Cronet"), 
          t[0] = !0, this.apply(e, t);
        }));
      } catch (e) {
        n.Log.d("Chromium Cronet pinner not found: " + e, "[-]");
      }
      try {
        e.hookMethods("diefferson.http_certificate_pinning.HttpCertificatePinning", "checkConnexion", (function(e, t) {
          return n.Log.d("Bypassing Flutter HttpCertificatePinning : " + t[0]), !0;
        }));
      } catch (e) {
        n.Log.d("Flutter HttpCertificatePinning pinner not found: " + e, "[-]");
      }
      try {
        e.hookMethods("javax.net.ssl.SSLPeerUnverifiedException", "$init", (function(t, r) {
          n.Log.w("Unexpected SSLPeerUnverifiedException occurred, trying to patch it dynamically...", "[!]");
          var o = Java.use("java.lang.Thread").currentThread().getStackTrace(), i = o.findIndex((function(e) {
            return "javax.net.ssl.SSLPeerUnverifiedException" === e.getClassName();
          })), a = o[i + 1], c = a.getClassName(), s = a.getMethodName();
          return e.hookMethods(c, s, (function(e, n) {
            return "void" == this.returnType.type ? void 0 : "boolean" === this.returnType.type || null;
          })), this.apply(t, r);
        }));
      } catch (e) {
        n.Log.d("SSLPeerUnverifiedException not found: " + e, "[-]");
      }
    }));
  }, r;
}(n.Base);

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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJpbmRleC50cyIsImxpYi9hbmRyb2lkLnRzIiwibGliL2Jhc2UudHMiLCJsaWIvamF2YS50cyIsImxpYi9vYmpjLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOzs7Ozs7O0FDQUEsSUFBQSxJQUFBLFFBQUEsZUFDQSxJQUFBLFFBQUEsZUFDQSxJQUFBLFFBQUEsZUFDQSxJQUFBLFFBQUE7O0FBRUEsV0FBVyxNQUFNLEVBQUEsS0FDakIsV0FBVyxhQUFhLElBQUksRUFBQSxZQUM1QixXQUFXLGFBQWEsSUFBSSxFQUFBO0FBQzVCLFdBQVcsZ0JBQWdCLElBQUksRUFBQTs7O0FDUi9CO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQzFVQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNsRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztBQ25LQSxJQUFBLElBQUEsUUFBQSxXQUVBLElBQUEsU0FBQTtFQUVJLFNBQUE7V0FDSSxFQUFBLEtBQUEsU0FBTzs7RUFFZixPQUxnQyxFQUFBLEdBQUEsSUFLaEM7Q0FMQSxDQUFnQyxFQUFBOztBQUFuQixRQUFBLGFBQUEiLCJmaWxlIjoiZ2VuZXJhdGVkLmpzIiwic291cmNlUm9vdCI6IiJ9
