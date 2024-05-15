(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.ScriptLoader = void 0;

var e = function() {
  function e() {
    var e = this;
    this.pendingEvents = [], this.flushTimer = null, this.flush = function() {
      if (null !== e.flushTimer && (clearTimeout(e.flushTimer), e.flushTimer = null), 
      0 !== e.pendingEvents.length) {
        var t = e.pendingEvents;
        e.pendingEvents = [], send({
          $events: t
        });
      }
    };
  }
  return e.prototype.emit = function(e, t, n) {
    var r = {};
    r[e] = t, null == n ? (this.pendingEvents.push(r), this.pendingEvents.length >= 50 ? this.flush() : null === this.flushTimer && (this.flushTimer = setTimeout(this.flush, 50))) : (this.flush(), 
    send({
      $events: [ r ]
    }, n));
  }, e;
}(), t = function() {
  function e() {}
  return e.prototype.emit = function(e, t) {
    o.emit("msg", e, t);
  }, e;
}(), n = function() {
  function e() {
    this.DEBUG = 1, this.INFO = 2, this.WARNING = 3, this.ERROR = 4, this.$level = this.INFO;
    var e = function(e) {
      return function() {
        for (var t = "", n = 0; n < arguments.length; n++) n > 0 && (t += " "), t += pretty2String(arguments[n]);
        e(t);
      };
    };
    console.debug = e(this.d.bind(this)), console.info = e(this.i.bind(this)), console.warn = e(this.w.bind(this)), 
    console.error = e(this.e.bind(this)), console.log = e(this.i.bind(this));
  }
  return Object.defineProperty(e.prototype, "level", {
    get: function() {
      return this.$level;
    },
    enumerable: !1,
    configurable: !0
  }), e.prototype.setLevel = function(e) {
    this.$level = e, this.d("Set log level: " + e);
  }, e.prototype.d = function(e, t) {
    this.$level <= this.DEBUG && o.emit("log", {
      level: "debug",
      message: e
    }, t);
  }, e.prototype.i = function(e, t) {
    this.$level <= this.INFO && o.emit("log", {
      level: "info",
      message: e
    }, t);
  }, e.prototype.w = function(e, t) {
    this.$level <= this.WARNING && o.emit("log", {
      level: "warning",
      message: e
    }, t);
  }, e.prototype.e = function(e, t) {
    this.$level <= this.ERROR && o.emit("log", {
      level: "error",
      message: e
    }, t);
  }, e;
}(), r = function() {
  function e() {}
  return e.prototype.load = function(e, t) {
    for (var n = 0, r = e; n < r.length; n++) {
      var i = r[n];
      try {
        var o = i.filename;
        o = (o = o.replace(/[\/\\]/g, "$")).replace(/[^A-Za-z0-9_$]+/g, "_"), o = "fn_".concat(o).substring(0, 255), 
        (0, eval)("(function ".concat(o, "(parameters) {").concat(i.source, "\n})\n") + "//# sourceURL=".concat(i.filename))(t);
      } catch (e) {
        var l = e.hasOwnProperty("stack") ? e.stack : e;
        throw new Error("Unable to load ".concat(i.filename, ": ").concat(l));
      }
    }
  }, e;
}();

exports.ScriptLoader = r;

var i = new r;

rpc.exports = {
  loadScripts: i.load.bind(i)
};

var o = new e, l = {}, s = require("./lib/c"), u = require("./lib/java"), a = require("./lib/android"), c = require("./lib/objc"), f = require("./lib/ios"), p = new t, v = new n, h = new s.CHelper, b = new u.JavaHelper, d = new a.AndroidHelper, g = new c.ObjCHelper, m = new f.IOSHelper;

Object.defineProperties(globalThis, {
  Emitter: {
    enumerable: !0,
    value: p
  },
  Log: {
    enumerable: !0,
    value: v
  },
  CHelper: {
    enumerable: !0,
    value: h
  },
  JavaHelper: {
    enumerable: !0,
    value: b
  },
  AndroidHelper: {
    enumerable: !0,
    value: d
  },
  ObjCHelper: {
    enumerable: !0,
    value: g
  },
  IOSHelper: {
    enumerable: !0,
    value: m
  },
  isFunction: {
    enumerable: !1,
    value: function(e) {
      return "[object Function]" === Object.prototype.toString.call(e);
    }
  },
  ignoreError: {
    enumerable: !1,
    value: function(e, t) {
      void 0 === t && (t = void 0);
      try {
        return e();
      } catch (e) {
        return v.d("Catch ignored error. " + e), t;
      }
    }
  },
  parseBoolean: {
    enumerable: !1,
    value: function(e, t) {
      if (void 0 === t && (t = void 0), "boolean" == typeof e) return e;
      if ("string" == typeof e) {
        var n = e.toLowerCase();
        if ("true" === n) return !0;
        if ("false" === n) return !1;
      }
      return t;
    }
  },
  pretty2String: {
    enumerable: !1,
    value: function(e) {
      return "string" != typeof e && (e = pretty2Json(e)), JSON.stringify(e);
    }
  },
  pretty2Json: {
    enumerable: !1,
    value: function(e) {
      if (!(e instanceof Object)) return e;
      if (Array.isArray(e)) {
        for (var t = [], n = 0; n < e.length; n++) t.push(pretty2Json(e[n]));
        return t;
      }
      return Java.available && b.isJavaObject(e) ? b.objectClass.toString.apply(e) : ignoreError((function() {
        return e.toString();
      }));
    }
  },
  getDebugSymbolFromAddress: {
    enumerable: !1,
    value: function(e) {
      var t = e.toString();
      return void 0 === l[t] && (l[t] = DebugSymbol.fromAddress(e)), l[t];
    }
  }
});

},{"./lib/android":2,"./lib/c":3,"./lib/ios":4,"./lib/java":5,"./lib/objc":6}],2:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.AndroidHelper = void 0;

var e = function() {
  function e() {
    this.$useClassCallbackMap = null;
  }
  return e.prototype.setWebviewDebuggingEnabled = function() {
    Log.w("Android Enable Webview Debugging"), Java.perform((function() {
      var e = "android.webkit.WebView";
      JavaHelper.hookMethods(e, "setWebContentsDebuggingEnabled", (function(e, o) {
        return Log.d("android.webkit.WebView.setWebContentsDebuggingEnabled: " + o[0]), 
        o[0] = !0, this(e, o);
      })), JavaHelper.hookMethods(e, "loadUrl", (function(e, o) {
        return Log.d("android.webkit.WebView.loadUrl: " + o[0]), e.setWebContentsDebuggingEnabled(!0), 
        this(e, o);
      }));
      ignoreError((function() {
        return JavaHelper.hookMethods(e, "setWebContentsDebuggingEnabled", (function(e, o) {
          return Log.d("com.uc.webview.export.WebView.setWebContentsDebuggingEnabled: " + o[0]), 
          o[0] = !0, this(e, o);
        }));
      })), ignoreError((function() {
        return JavaHelper.hookMethods("com.uc.webview.export.WebView", "loadUrl", (function(e, o) {
          return Log.d("com.uc.webview.export.WebView.loadUrl: " + o[0]), e.setWebContentsDebuggingEnabled(!0), 
          this(e, o);
        }));
      }));
    }));
  }, e.prototype.bypassSslPinning = function() {
    Log.w("Android Bypass ssl pinning"), Java.perform((function() {
      var e = Java.use("java.util.Arrays");
      ignoreError((function() {
        return JavaHelper.hookMethods("com.android.org.conscrypt.TrustManagerImpl", "checkServerTrusted", (function(o, n) {
          if (Log.d("SSL bypassing " + this), "void" != this.returnType.type) return "pointer" == this.returnType.type && "java.util.List" == this.returnType.className ? e.asList(n[0]) : void 0;
        }));
      })), ignoreError((function() {
        return JavaHelper.hookMethods("com.google.android.gms.org.conscrypt.Platform", "checkServerTrusted", (function(e, o) {
          Log.d("SSL bypassing " + this);
        }));
      })), ignoreError((function() {
        return JavaHelper.hookMethods("com.android.org.conscrypt.Platform", "checkServerTrusted", (function(e, o) {
          Log.d("SSL bypassing " + this);
        }));
      })), ignoreError((function() {
        return JavaHelper.hookMethods("okhttp3.CertificatePinner", "check", (function(e, o) {
          if (Log.d("SSL bypassing " + this), "boolean" == this.returnType.type) return !0;
        }));
      })), ignoreError((function() {
        return JavaHelper.hookMethods("okhttp3.CertificatePinner", "check$okhttp", (function(e, o) {
          Log.d("SSL bypassing " + this);
        }));
      })), ignoreError((function() {
        return JavaHelper.hookMethods("com.android.okhttp.CertificatePinner", "check", (function(e, o) {
          if (Log.d("SSL bypassing " + this), "boolean" == this.returnType.type) return !0;
        }));
      })), ignoreError((function() {
        return JavaHelper.hookMethods("com.android.okhttp.CertificatePinner", "check$okhttp", (function(e, o) {
          Log.d("SSL bypassing " + this);
        }));
      })), ignoreError((function() {
        return JavaHelper.hookMethods("com.android.org.conscrypt.TrustManagerImpl", "verifyChain", (function(e, o) {
          return Log.d("SSL bypassing " + this), o[0];
        }));
      }));
    }));
  }, e.prototype.chooseClassLoader = function(e) {
    Log.w("choose classloder: " + e), Java.perform((function() {
      Java.enumerateClassLoaders({
        onMatch: function(o) {
          try {
            null != o.findClass(e) && (Log.i("choose classloader: " + o), Reflect.set(Java.classFactory, "loader", o));
          } catch (e) {
            Log.e(pretty2Json(e));
          }
        },
        onComplete: function() {
          Log.d("enumerate classLoaders complete");
        }
      });
    }));
  }, e.prototype.traceClasses = function(e, o, n) {
    void 0 === o && (o = void 0), void 0 === n && (n = void 0), e = null != e ? e.trim().toLowerCase() : "", 
    o = null != o ? o.trim().toLowerCase() : "", n = null != n ? n : {
      stack: !0,
      args: !0
    }, Log.w("trace classes, include: " + e + ", exclude: " + o + ", options: " + JSON.stringify(n)), 
    Java.perform((function() {
      Java.enumerateLoadedClasses({
        onMatch: function(t) {
          var r = t.toString().toLowerCase();
          r.indexOf(e) >= 0 && ("" == o || r.indexOf(o) < 0) && JavaHelper.hookAllMethods(t, JavaHelper.getEventImpl(n));
        },
        onComplete: function() {
          Log.d("enumerate classLoaders complete");
        }
      });
    }));
  }, e.prototype.runOnCreateContext = function(e) {
    Java.perform((function() {
      JavaHelper.hookMethods("android.app.ContextImpl", "createAppContext", (function(o, n) {
        var t = this(o, n);
        return e(t), t;
      }));
    }));
  }, e.prototype.runOnCreateApplication = function(e) {
    Java.perform((function() {
      JavaHelper.hookMethods("android.app.LoadedApk", "makeApplication", (function(o, n) {
        var t = this(o, n);
        return e(t), t;
      }));
    }));
  }, e.prototype.javaUse = function(e, o) {
    var n = this;
    Java.perform((function() {
      var t = null;
      try {
        t = JavaHelper.findClass(e);
      } catch (t) {
        var r;
        if (null == n.$useClassCallbackMap && (n.$useClassCallbackMap = new Map, n.$registerUseClassCallback(n.$useClassCallbackMap)), 
        n.$useClassCallbackMap.has(e)) void 0 !== (r = n.$useClassCallbackMap.get(e)) && r.add(o); else (r = new Set).add(o), 
        n.$useClassCallbackMap.set(e, r);
        return;
      }
      o(t);
    }));
  }, e.prototype.$registerUseClassCallback = function(e) {
    var o = Java.use("java.util.HashSet").$new(), n = function(o) {
      for (var n, t = e.entries(), r = function() {
        var t = n.value[0], r = n.value[1], a = null;
        try {
          a = JavaHelper.findClass(t, o);
        } catch (e) {}
        null != a && (e.delete(t), r.forEach((function(e, o, n) {
          e(a);
        })));
      }; !(n = t.next()).done; ) r();
    };
    JavaHelper.hookMethod("java.lang.Class", "forName", [ "java.lang.String", "boolean", "java.lang.ClassLoader" ], (function(e, t) {
      var r = t[2];
      return null == r || o.contains(r) || (o.add(r), n(r)), this(e, t);
    })), JavaHelper.hookMethod("java.lang.ClassLoader", "loadClass", [ "java.lang.String", "boolean" ], (function(e, t) {
      var r = e;
      return o.contains(r) || (o.add(r), n(r)), this(e, t);
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
      return this.getExportFunction(null, "dlopen", "pointer", [ "pointer", "int" ]);
    },
    enumerable: !1,
    configurable: !0
  }), t.prototype.getExportFunction = function(t, e, r, n) {
    var o = (t || "") + "|" + e;
    if (o in this.$funcCaches) return this.$funcCaches[o];
    var a = Module.findExportByName(t, e);
    if (null === a) throw Error("cannot find " + e);
    return this.$funcCaches[o] = new NativeFunction(a, r, n), this.$funcCaches[o];
  }, t.prototype.hookFunctionWithOptions = function(t, e, r) {
    return this.hookFunctionWithCallbacks(t, e, this.getEventImpl(r));
  }, t.prototype.hookFunctionWithCallbacks = function(t, e, r) {
    var n = Module.findExportByName(t, e);
    if (null === n) throw Error("cannot find " + e);
    var o = {
      get: function(t, r, n) {
        return "name" === r ? e : t[r];
      }
    }, a = {};
    "onEnter" in r && (a.onEnter = function(t) {
      r.onEnter.call(new Proxy(this, o), t);
    }), "onLeave" in r && (a.onLeave = function(t) {
      r.onLeave.call(new Proxy(this, o), t);
    });
    var i = Interceptor.attach(n, a);
    return Log.i("Hook function: " + e + " (" + n + ")"), i;
  }, t.prototype.hookFunction = function(t, e, r, n, o) {
    var a = this.getExportFunction(t, e, r, n);
    if (null === a) throw Error("cannot find " + e);
    isFunction(o) || (o = this.getEventImpl(o));
    var i = n;
    Interceptor.replace(a, new NativeCallback((function() {
      for (var t = this, i = [], c = 0; c < n.length; c++) i[c] = arguments[c];
      var s = new Proxy(a, {
        get: function(o, a, i) {
          switch (a) {
           case "name":
            return e;

           case "argumentTypes":
            return n;

           case "returnType":
            return r;

           case "context":
            return t.context;

           default:
            o[a];
          }
        },
        apply: function(t, e, r) {
          return t.apply(null, r[0]);
        }
      });
      return o.call(s, i);
    }), r, i)), Log.i("Hook function: " + e + " (" + a + ")");
  }, t.prototype.getEventImpl = function(t) {
    var e = new function() {
      for (var e in this.method = !0, this.thread = !1, this.stack = !1, this.args = !1, 
      this.extras = {}, t) e in this ? this[e] = t[e] : this.extras[e] = t[e];
    }, r = function(t) {
      var r = {};
      for (var n in e.extras) r[n] = e.extras[n];
      !1 !== e.method && (r.method_name = this.name), !1 !== e.thread && (r.thread_id = Process.getCurrentThreadId()), 
      !1 !== e.args && (r.args = pretty2Json(t), r.result = null, r.error = null);
      try {
        var o = this(t);
        return !1 !== e.args && (r.result = pretty2Json(o)), o;
      } catch (t) {
        throw !1 !== e.args && (r.error = pretty2Json(t)), t;
      } finally {
        if (!1 !== e.stack) {
          for (var a = [], i = "fuzzy" !== e.stack ? Backtracer.ACCURATE : Backtracer.FUZZY, c = Thread.backtrace(this.context, i), s = 0; s < c.length; s++) a.push(getDebugSymbolFromAddress(c[s]).toString());
          r.stack = a;
        }
        Emitter.emit(r);
      }
    };
    return r.onLeave = function(t) {
      var r = {};
      for (var n in e.extras) r[n] = e.extras[n];
      if (!1 !== e.method && (r.method_name = this.name), !1 !== e.thread && (r.thread_id = Process.getCurrentThreadId()), 
      !1 !== e.args && (r.result = pretty2Json(t)), !1 !== e.stack) {
        for (var o = [], a = "fuzzy" !== e.stack ? Backtracer.ACCURATE : Backtracer.FUZZY, i = Thread.backtrace(this.context, a), c = 0; c < i.length; c++) o.push(getDebugSymbolFromAddress(i[c]).toString());
        r.stack = o;
      }
      Emitter.emit(r);
    }, r;
  }, t;
}();

exports.CHelper = t;

},{}],4:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.IOSHelper = void 0;

var t = function() {
  function t() {}
  return t.prototype.bypassSslPinning = function() {
    Log.w("iOS Bypass ssl pinning");
    try {
      Module.ensureInitialized("libboringssl.dylib");
    } catch (t) {
      Log.d("libboringssl.dylib module not loaded. Trying to manually load it."), Module.load("libboringssl.dylib");
    }
    var t = new NativeCallback((function(t, i) {
      return Log.d("custom SSL context verify callback, returning SSL_VERIFY_NONE"), 0;
    }), "int", [ "pointer", "pointer" ]);
    try {
      CHelper.hookFunction("libboringssl.dylib", "SSL_set_custom_verify", "void", [ "pointer", "int", "pointer" ], (function(i) {
        return Log.d("SSL_set_custom_verify(), setting custom callback."), i[2] = t, this(i);
      }));
    } catch (i) {
      CHelper.hookFunction("libboringssl.dylib", "SSL_CTX_set_custom_verify", "void", [ "pointer", "int", "pointer" ], (function(i) {
        return Log.d("SSL_CTX_set_custom_verify(), setting custom callback."), i[2] = t, 
        this(i);
      }));
    }
    CHelper.hookFunction("libboringssl.dylib", "SSL_get_psk_identity", "pointer", [ "pointer" ], (function(t) {
      return Log.d('SSL_get_psk_identity(), returning "fakePSKidentity"'), Memory.allocUtf8String("fakePSKidentity");
    }));
  }, t;
}();

exports.IOSHelper = t;

},{}],5:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.JavaHelper = void 0;

var e = function() {
  function e() {
    this.excludeHookPackages = [ "java.", "javax.", "android.", "androidx." ];
  }
  return Object.defineProperty(e.prototype, "objectClass", {
    get: function() {
      return Java.use("java.lang.Object");
    },
    enumerable: !1,
    configurable: !0
  }), Object.defineProperty(e.prototype, "classClass", {
    get: function() {
      return Java.use("java.lang.Class");
    },
    enumerable: !1,
    configurable: !0
  }), Object.defineProperty(e.prototype, "stringClass", {
    get: function() {
      return Java.use("java.lang.String");
    },
    enumerable: !1,
    configurable: !0
  }), Object.defineProperty(e.prototype, "threadClass", {
    get: function() {
      return Java.use("java.lang.Thread");
    },
    enumerable: !1,
    configurable: !0
  }), Object.defineProperty(e.prototype, "throwableClass", {
    get: function() {
      return Java.use("java.lang.Throwable");
    },
    enumerable: !1,
    configurable: !0
  }), Object.defineProperty(e.prototype, "uriClass", {
    get: function() {
      return Java.use("android.net.Uri");
    },
    enumerable: !1,
    configurable: !0
  }), Object.defineProperty(e.prototype, "urlClass", {
    get: function() {
      return Java.use("java.net.URL");
    },
    enumerable: !1,
    configurable: !0
  }), Object.defineProperty(e.prototype, "mapClass", {
    get: function() {
      return Java.use("java.util.Map");
    },
    enumerable: !1,
    configurable: !0
  }), Object.defineProperty(e.prototype, "applicationContext", {
    get: function() {
      return Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
    },
    enumerable: !1,
    configurable: !0
  }), e.prototype.isSameObject = function(e, t) {
    return e === t || null != e && null != t && (!!e.hasOwnProperty("$isSameObject") && e.$isSameObject(t));
  }, e.prototype.getObjectHandle = function(e) {
    if (null == e) return null;
    if (e.hasOwnProperty("$h")) return e.$h;
    throw new Error("not implemented for 'getObjectHandle'");
  }, e.prototype.getClassName = function(e) {
    var t = e.$className;
    if (null != t) return t;
    if (null != (t = e.__name__)) return t;
    if (null != e.$classWrapper) {
      if (null != (t = e.$classWrapper.$className)) return t;
      if (null != (t = e.$classWrapper.__name__)) return t;
    }
    Log.e("Cannot get class name: " + e);
  }, e.prototype.getClassMethod = function(e, t) {
    var r = e[t];
    return void 0 !== r || "$" == t[0] && void 0 !== (r = e["_" + t]) ? r : void 0;
  }, e.prototype.$prettyClassName = function(e) {
    if (e.startsWith("[L") && e.endsWith(";")) return "".concat(e.substring(2, e.length - 1), "[]");
    if (e.startsWith("[")) switch (e.substring(1, 2)) {
     case "B":
      return "byte[]";

     case "C":
      return "char[]";

     case "D":
      return "double[]";

     case "F":
      return "float[]";

     case "I":
      return "int[]";

     case "S":
      return "short[]";

     case "J":
      return "long[]";

     case "Z":
      return "boolean[]";

     case "V":
      return "void[]";
    }
    return e;
  }, e.prototype.$defineMethodProperties = function(e) {
    var t = this;
    Object.defineProperties(e, {
      className: {
        configurable: !0,
        enumerable: !0,
        writable: !1,
        value: this.getClassName(e.holder)
      },
      name: {
        configurable: !0,
        enumerable: !0,
        get: function() {
          var e = t.$prettyClassName(this.returnType.className), r = t.$prettyClassName(this.className) + "." + this.methodName, a = "";
          if (this.argumentTypes.length > 0) {
            a = t.$prettyClassName(this.argumentTypes[0].className);
            for (var n = 1; n < this.argumentTypes.length; n++) a = a + ", " + t.$prettyClassName(this.argumentTypes[n].className);
          }
          return e + " " + r + "(" + a + ")";
        }
      },
      toString: {
        configurable: !0,
        value: function() {
          return this.name;
        }
      }
    });
  }, e.prototype.findClass = function(e, t) {
    if (void 0 === t && (t = void 0), void 0 !== t && null != t) return Java.ClassFactory.get(t).use(e);
    if (parseInt(Java.androidVersion) < 7) return Java.use(e);
    var r = null, a = Java.enumerateClassLoadersSync();
    for (var n in a) try {
      var o = this.findClass(e, a[n]);
      if (null != o) return o;
    } catch (e) {
      null == r && (r = e);
    }
    throw r;
  }, e.prototype.$hookMethod = function(e, t) {
    if (void 0 === t && (t = null), null != t) {
      var r = new Proxy(e, {
        apply: function(e, t, r) {
          var a = r[0], n = r[1];
          return e.apply(a, n);
        }
      });
      isFunction(t) || (t = this.getEventImpl(t)), e.implementation = function() {
        return t.call(r, this, Array.prototype.slice.call(arguments));
      }, Log.i("Hook method: " + e);
    } else e.implementation = null, Log.i("Unhook method: " + e);
  }, e.prototype.hookMethod = function(e, t, r, a) {
    void 0 === a && (a = null);
    var n = t;
    if ("string" == typeof n) {
      var o = n, s = e;
      "string" == typeof s && (s = this.findClass(s));
      var i = this.getClassMethod(s, o);
      if (void 0 === i || void 0 === i.overloads) throw Error("Cannot find method: " + this.getClassName(s) + "." + o);
      if (null != r) {
        var l = r;
        for (var u in l) "string" != typeof l[u] && (l[u] = this.getClassName(l[u]));
        n = i.overload.apply(i, l);
      } else {
        if (1 != i.overloads.length) throw Error(this.getClassName(s) + "." + o + " has too many overloads");
        n = i.overloads[0];
      }
    }
    this.$defineMethodProperties(n), this.$hookMethod(n, a);
  }, e.prototype.hookMethods = function(e, t, r) {
    void 0 === r && (r = null);
    var a = e;
    "string" == typeof a && (a = this.findClass(a));
    var n = this.getClassMethod(a, t);
    if (void 0 === n || void 0 === n.overloads) throw Error("Cannot find method: " + this.getClassName(a) + "." + t);
    for (var o = 0; o < n.overloads.length; o++) {
      var s = n.overloads[o];
      void 0 !== s.returnType && void 0 !== s.returnType.className && (this.$defineMethodProperties(s), 
      this.$hookMethod(s, r));
    }
  }, e.prototype.hookAllConstructors = function(e, t) {
    void 0 === t && (t = null);
    var r = e;
    "string" == typeof r && (r = this.findClass(r)), this.hookMethods(r, "$init", t);
  }, e.prototype.$isExcludeClass = function(e) {
    for (var t in this.excludeHookPackages) if (0 == e.indexOf(this.excludeHookPackages[t])) return !0;
    return !1;
  }, e.prototype.hookAllMethods = function(e, t) {
    void 0 === t && (t = null);
    var r = e;
    "string" == typeof r && (r = this.findClass(r));
    for (var a = [], n = null, o = r.class; null != o; ) {
      for (var s = o.getDeclaredMethods(), i = 0; i < s.length; i++) {
        var l = s[i].getName();
        a.indexOf(l) < 0 && (a.push(l), this.hookMethods(r, l, t));
      }
      if (n = o.getSuperclass(), o.$dispose(), null == n) break;
      if (o = Java.cast(n, this.classClass), this.$isExcludeClass(o.getName())) break;
    }
  }, e.prototype.hookClass = function(e, t) {
    void 0 === t && (t = null);
    var r = e;
    "string" == typeof r && (r = this.findClass(r)), this.hookAllConstructors(r, t), 
    this.hookAllMethods(r, t);
  }, e.prototype.getEventImpl = function(e) {
    var t = this, r = new function() {
      for (var t in this.method = !0, this.thread = !1, this.stack = !1, this.args = !1, 
      this.extras = {}, e) t in this ? this[t] = e[t] : this.extras[t] = e[t];
    };
    return function(e, a) {
      var n = {};
      for (var o in r.extras) n[o] = r.extras[o];
      !1 !== r.method && (n.class_name = e.$className, n.method_name = this.name, n.method_simple_name = this.methodName), 
      !1 !== r.thread && (n.thread_id = Process.getCurrentThreadId(), n.thread_name = t.threadClass.currentThread().getName()), 
      !1 !== r.args && (n.args = pretty2Json(a), n.result = null, n.error = null);
      try {
        var s = this(e, a);
        return !1 !== r.args && (n.result = pretty2Json(s)), s;
      } catch (e) {
        throw !1 !== r.args && (n.error = pretty2Json(e)), e;
      } finally {
        !1 !== r.stack && (n.stack = pretty2Json(t.getStackTrace())), Emitter.emit(n);
      }
    };
  }, e.prototype.isJavaObject = function(e) {
    if (e instanceof Object && e.hasOwnProperty("class") && e.class instanceof Object) {
      var t = e.class;
      if (t.hasOwnProperty("getName") && t.hasOwnProperty("getDeclaredClasses") && t.hasOwnProperty("getDeclaredFields") && t.hasOwnProperty("getDeclaredMethods")) return !0;
    }
    return !1;
  }, e.prototype.isJavaArray = function(e) {
    if (e instanceof Object && e.hasOwnProperty("class") && e.class instanceof Object) {
      var t = e.class;
      if (t.hasOwnProperty("isArray") && t.isArray()) return !0;
    }
    return !1;
  }, e.prototype.fromJavaArray = function(e, t) {
    var r = e;
    "string" == typeof r && (r = this.findClass(r));
    for (var a = [], n = Java.vm.getEnv(), o = 0; o < n.getArrayLength(t.$handle); o++) a.push(Java.cast(n.getObjectArrayElement(t.$handle, o), r));
    return a;
  }, e.prototype.getJavaEnumValue = function(e, t) {
    var r = e;
    "string" == typeof r && (r = this.findClass(r));
    var a = r.class.getEnumConstants();
    a instanceof Array || (a = this.fromJavaArray(r, a));
    for (var n = 0; n < a.length; n++) if (a[n].toString() === t) return a[n];
    throw new Error("Name of " + t + " does not match " + r);
  }, e.prototype.getStackTrace = function() {
    for (var e = [], t = this.throwableClass.$new().getStackTrace(), r = 0; r < t.length; r++) e.push(t[r]);
    return e;
  }, e;
}();

exports.JavaHelper = e;

},{}],6:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.ObjCHelper = void 0;

var t = function() {
  function t() {}
  return t.prototype.$defineMethodProperties = function(t, e) {
    var r = e.origImplementation || e.implementation, n = t.toString(), o = ObjC.selectorAsString(e.selector), i = ObjC.classes.NSThread.hasOwnProperty(o);
    Object.defineProperties(e, {
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
          return o;
        }
      },
      name: {
        configurable: !0,
        enumerable: !0,
        get: function() {
          return (i ? "+" : "-") + "[" + n + " " + o + "]";
        }
      },
      origImplementation: {
        configurable: !0,
        enumerable: !0,
        get: function() {
          return r;
        }
      },
      toString: {
        value: function() {
          return this.name;
        }
      }
    });
  }, t.prototype.$hookMethod = function(t, e) {
    void 0 === e && (e = null), null != e ? (isFunction(e) || (e = this.getEventImpl(e)), 
    t.implementation = ObjC.implement(t, (function() {
      var r = this, n = Array.prototype.slice.call(arguments), o = n.shift(), i = n.shift(), a = new Proxy(t, {
        get: function(t, e, n) {
          return e in r ? r[e] : t[e];
        },
        apply: function(t, e, r) {
          var n = r[0], o = r[1];
          return t.origImplementation.apply(null, [].concat(n, i, o));
        }
      });
      return e.call(a, o, n);
    })), Log.i("Hook method: " + t)) : (t.implementation = t.origImplementation, Log.i("Unhook method: " + pretty2String(t)));
  }, t.prototype.hookMethod = function(t, e, r) {
    void 0 === r && (r = null);
    var n = t;
    if ("string" == typeof n && (n = ObjC.classes[n]), void 0 === n) throw Error('cannot find class "' + t + '"');
    var o = e;
    if ("string" == typeof o && (o = n[o]), void 0 === o) throw Error('cannot find method "' + e + '" in class "' + n + '"');
    this.$defineMethodProperties(n, o), this.$hookMethod(o, r);
  }, t.prototype.hookMethods = function(t, e, r) {
    void 0 === r && (r = null);
    var n = t;
    if ("string" == typeof n && (n = ObjC.classes[n]), void 0 === n) throw Error('cannot find class "' + t + '"');
    for (var o = n.$ownMethods.length, i = 0; i < o; i++) {
      var a = n.$ownMethods[i];
      if (a.indexOf(e) >= 0) {
        var s = n[a];
        this.$defineMethodProperties(n, s), this.$hookMethod(s, r);
      }
    }
  }, t.prototype.getEventImpl = function(t) {
    var e = this, r = new function() {
      for (var e in this.method = !0, this.thread = !1, this.stack = !1, this.args = !1, 
      this.extras = {}, t) e in this ? this[e] = t[e] : this.extras[e] = t[e];
    };
    return function(t, n) {
      var o = {};
      for (var i in r.extras) o[i] = r.extras[i];
      if (!1 !== r.method && (o.class_name = new ObjC.Object(t).$className, o.method_name = this.name, 
      o.method_simple_name = this.methodName), !1 !== r.thread && (o.thread_id = Process.getCurrentThreadId(), 
      o.thread_name = ObjC.classes.NSThread.currentThread().name().toString()), !1 !== r.args) {
        for (var a = [], s = 0; s < n.length; s++) a.push(e.convert2ObjcObject(n[s]));
        o.args = pretty2Json(a), o.result = null, o.error = null;
      }
      try {
        var c = this(t, n);
        return !1 !== r.args && (o.result = pretty2Json(e.convert2ObjcObject(c))), c;
      } catch (t) {
        throw !1 !== r.args && (o.error = pretty2Json(t)), t;
      } finally {
        if (!1 !== r.stack) {
          var h = [], l = "fuzzy" !== r.stack ? Backtracer.ACCURATE : Backtracer.FUZZY, u = Thread.backtrace(this.context, l);
          for (s = 0; s < u.length; s++) h.push(getDebugSymbolFromAddress(u[s]).toString());
          o.stack = h;
        }
        Emitter.emit(o);
      }
    };
  }, t.prototype.convert2ObjcObject = function(t) {
    return t instanceof NativePointer || "object" == typeof t && t.hasOwnProperty("handle") ? new ObjC.Object(t) : t;
  }, t;
}();

exports.ObjCHelper = t;

},{}]},{},[1])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJpbmRleC50cyIsImxpYi9hbmRyb2lkLnRzIiwibGliL2MudHMiLCJsaWIvaW9zLnRzIiwibGliL2phdmEudHMiLCJsaWIvb2JqYy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7Ozs7OztBQ0tBLElBQUEsSUFBQTtFQUFBLFNBQUE7SUFBQSxJQUFBLElBQUE7SUFFWSxLQUFBLGdCQUF1QixJQUN2QixLQUFBLGFBQWtCLE1Bd0JsQixLQUFBLFFBQVE7TUFNWixJQUx3QixTQUFwQixFQUFLLGVBQ0wsYUFBYSxFQUFLLGFBQ2xCLEVBQUssYUFBYTtNQUdZLE1BQTlCLEVBQUssY0FBYyxRQUF2QjtRQUlBLElBQU0sSUFBUyxFQUFLO1FBQ3BCLEVBQUssZ0JBQWdCLElBRXJCLEtBQUs7VUFBRSxTQUFTOzs7QUFDcEI7QUFDSjtFQUFBLE9BckNJLEVBQUEsVUFBQSxPQUFBLFNBQUssR0FBYyxHQUFjO0lBQzdCLElBQU0sSUFBUTtJQUNkLEVBQU0sS0FBUSxHQUVGLFFBQVIsS0FFQSxLQUFLLGNBQWMsS0FBSyxJQUNwQixLQUFLLGNBQWMsVUFBVSxLQUc3QixLQUFLLFVBQ3NCLFNBQXBCLEtBQUssZUFDWixLQUFLLGFBQWEsV0FBVyxLQUFLLE9BQU8sU0FLN0MsS0FBSztJQUNMLEtBQUs7TUFBRSxTQUFTLEVBQUM7T0FBVTtBQUVuQyxLQWlCSjtBQUFBLENBMUNBLElBNkNBLElBQUE7RUFBQSxTQUFBLEtBS0E7RUFBQSxPQUhJLEVBQUEsVUFBQSxPQUFBLFNBQUssR0FBYztJQUNmLEVBQWMsS0FBSyxPQUFPLEdBQVM7QUFDdkMsS0FDSjtBQUFBLENBTEEsSUFZQSxJQUFBO0VBUUksU0FBQTtJQU5BLEtBQUEsUUFBUSxHQUNSLEtBQUEsT0FBTyxHQUNQLEtBQUEsVUFBVSxHQUNWLEtBQUEsUUFBUSxHQUNBLEtBQUEsU0FBUyxLQUFLO0lBR2xCLElBQU0sSUFBVyxTQUFXO01BQ3hC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QUFRO01BSXBCLFlBSHFDLE1BQWpDLEVBQXdCLE9BQ3hCLEVBQXdCLEtBQU8sWUFBWSxZQUFZLEtBRXBELEVBQXdCO0FBQ25DOzs7OztBQ3pUUjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7Ozs7Ozs7QUM1SUEsSUFBQSxJQUFBO0VBQUEsU0FBQTtJQUVJLEtBQUEsY0FBYztBQXdObEI7RUFBQSxPQXROSSxPQUFBLGVBQUksRUFBQSxXQUFBLFVBQU07U0FBVjtNQUNJLE9BQU8sS0FBSyxrQkFBa0IsTUFBTSxVQUFVLFdBQVcsRUFBQyxXQUFXO0FBQ3pFOzs7TUFFQSxFQUFBLFVBQUEsb0JBQUEsU0FDSSxHQUNBLEdBQ0EsR0FDQTtJQUVBLElBQU0sS0FBTyxLQUFjLE1BQU0sTUFBTTtJQUN2QyxJQUFJLEtBQU8sS0FBSyxhQUNaLE9BQU8sS0FBSyxZQUFZO0lBRTVCLElBQUksSUFBTSxPQUFPLGlCQUFpQixHQUFZO0lBQzlDLElBQVksU0FBUixHQUNBLE1BQU0sTUFBTSxpQkFBaUI7SUFHakMsT0FEQSxLQUFLLFlBQVksS0FBTyxJQUFJLGVBQWUsR0FBSyxHQUFTLElBQ2xELEtBQUssWUFBWTtBQUM1QixLQVNBLEVBQUEsVUFBQSwwQkFBQSxTQUF3QixHQUEyQixHQUFvQjtJQUNuRSxPQUFPLEtBQUssMEJBQTBCLEdBQVksR0FBWSxLQUFLLGFBQWE7QUFDcEYsS0FTQSxFQUFBLFVBQUEsNEJBQUEsU0FBMEIsR0FBMkIsR0FBb0I7SUFDckUsSUFBTSxJQUFVLE9BQU8saUJBQWlCLEdBQVk7SUFDcEQsSUFBZ0IsU0FBWixHQUNBLE1BQU0sTUFBTSxpQkFBaUI7SUFFakMsSUFBTSxJQUFlO01BQ2pCLEtBQUssU0FBVSxHQUFRLEdBQW9CO1FBQ3ZDLE9BQ1MsV0FERCxJQUNnQixJQUNKLEVBQU87QUFFL0I7T0FFRSxJQUFLO0lBQ1AsYUFBYSxNQUNiLEVBQVksVUFBSSxTQUFVO01BQ04sRUFBVSxRQUN2QixLQUFLLElBQUksTUFBTSxNQUFNLElBQWU7QUFDM0MsUUFFQSxhQUFhLE1BQ2IsRUFBWSxVQUFJLFNBQVU7TUFDTixFQUFVLFFBQ3ZCLEtBQUssSUFBSSxNQUFNLE1BQU0sSUFBZTtBQUMzQztJQUVKLElBQU0sSUFBUyxZQUFZLE9BQU8sR0FBUztJQUUzQyxPQURBLElBQUksRUFBRSxvQkFBb0IsSUFBYSxPQUFPLElBQVUsTUFDakQ7QUFDWCxLQVdBLEVBQUEsVUFBQSxlQUFBLFNBQ0ksR0FDQSxHQUNBLEdBQ0EsR0FDQTtJQUVBLElBQU0sSUFBTyxLQUFLLGtCQUFrQixHQUFZLEdBQVksR0FBUztJQUNyRSxJQUFhLFNBQVQsR0FDQSxNQUFNLE1BQU0saUJBQWlCO0lBRTVCLFdBQVcsT0FDWixJQUFPLEtBQUssYUFBYTtJQUc3QixJQUFNLElBQXdCO0lBQzlCLFlBQVksUUFBUSxHQUFNLElBQUksZ0JBQWU7TUFHekMsS0FGQSxJQUFNLElBQVksTUFDWixJQUFhLElBQ1YsSUFBSSxHQUFHLElBQUksRUFBUyxRQUFRLEtBQ2pDLEVBQVcsS0FBSyxVQUFVO01BRTlCLElBQU0sSUFBUSxJQUFJLE1BQU0sR0FBTTtRQUMxQixLQUFLLFNBQVUsR0FBUSxHQUFvQjtVQUN2QyxRQUFRO1dBQ0osS0FBSztZQUFRLE9BQU87O1dBQ3BCLEtBQUs7WUFBaUIsT0FBTzs7V0FDN0IsS0FBSztZQUFjLE9BQU87O1dBQzFCLEtBQUs7WUFBVyxPQUFPLEVBQUs7O1dBQzVCO1lBQVMsRUFBTzs7QUFFeEI7UUFDQSxPQUFPLFNBQVUsR0FBUSxHQUFjO1VBRW5DLE9BRGUsRUFDTixNQUFNLE1BQU0sRUFBUztBQUNsQzs7TUFFSixPQUFPLEVBQUssS0FBSyxHQUFPO0FBQzVCLFFBQUcsR0FBUyxLQUVaLElBQUksRUFBRSxvQkFBb0IsSUFBYSxPQUFPLElBQU87QUFDekQsS0FPQSxFQUFBLFVBQUEsZUFBQSxTQUFhO0lBQ1QsSUFBTSxJQUFPLElBQUk7TUFNYixLQUFLLElBQU0sS0FMWCxLQUFLLFVBQVMsR0FDZCxLQUFLLFVBQVMsR0FDZCxLQUFLLFNBQVEsR0FDYixLQUFLLFFBQU87TUFDWixLQUFLLFNBQVMsSUFDSSxHQUNWLEtBQU8sT0FDUCxLQUFLLEtBQU8sRUFBUSxLQUVwQixLQUFLLE9BQU8sS0FBTyxFQUFRO0FBR3ZDLE9BRU0sSUFBUyxTQUFVO01BQ3JCLElBQU0sSUFBUTtNQUNkLEtBQUssSUFBTSxLQUFPLEVBQUssUUFDbkIsRUFBTSxLQUFPLEVBQUssT0FBTztPQUVULE1BQWhCLEVBQUssV0FDTCxFQUFtQixjQUFJLEtBQUssUUFFWixNQUFoQixFQUFLLFdBQ0wsRUFBaUIsWUFBSSxRQUFRO09BRWYsTUFBZCxFQUFLLFNBQ0wsRUFBWSxPQUFJLFlBQVksSUFDNUIsRUFBYyxTQUFJLE1BQ2xCLEVBQWEsUUFBSTtNQUVyQjtRQUNJLElBQU0sSUFBUyxLQUFLO1FBSXBCLFFBSGtCLE1BQWQsRUFBSyxTQUNMLEVBQWMsU0FBSSxZQUFZLEtBRTNCO1FBQ1QsT0FBTztRQUlMLE9BSGtCLE1BQWQsRUFBSyxTQUNMLEVBQWEsUUFBSSxZQUFZLEtBRTNCOztRQUVOLEtBQW1CLE1BQWYsRUFBSyxPQUFpQjtVQUl0QixLQUhBLElBQU0sSUFBUSxJQUNSLElBQTRCLFlBQWYsRUFBSyxRQUFvQixXQUFXLFdBQVcsV0FBVyxPQUN2RSxJQUFXLE9BQU8sVUFBVSxLQUFLLFNBQVMsSUFDdkMsSUFBSSxHQUFHLElBQUksRUFBUyxRQUFRLEtBQ2pDLEVBQU0sS0FBSywwQkFBMEIsRUFBUyxJQUFJO1VBRXRELEVBQWEsUUFBSTs7UUFFckIsUUFBUSxLQUFLOztBQUVyQjtJQTRCQSxPQTFCQSxFQUFnQixVQUFJLFNBQVU7TUFDMUIsSUFBTSxJQUFRO01BQ2QsS0FBSyxJQUFNLEtBQU8sRUFBSyxRQUNuQixFQUFNLEtBQU8sRUFBSyxPQUFPO01BVzdCLEtBVG9CLE1BQWhCLEVBQUssV0FDTCxFQUFtQixjQUFJLEtBQUssUUFFWixNQUFoQixFQUFLLFdBQ0wsRUFBaUIsWUFBSSxRQUFRO09BRWYsTUFBZCxFQUFLLFNBQ0wsRUFBYyxTQUFJLFlBQVksTUFFZixNQUFmLEVBQUssT0FBaUI7UUFJdEIsS0FIQSxJQUFNLElBQVEsSUFDUixJQUE0QixZQUFmLEVBQUssUUFBb0IsV0FBVyxXQUFXLFdBQVcsT0FDdkUsSUFBVyxPQUFPLFVBQVUsS0FBSyxTQUFTLElBQ3ZDLElBQUksR0FBRyxJQUFJLEVBQVMsUUFBUSxLQUNqQyxFQUFNLEtBQUssMEJBQTBCLEVBQVMsSUFBSTtRQUV0RCxFQUFhLFFBQUk7O01BRXJCLFFBQVEsS0FBSztBQUNqQixPQUVPO0FBQ1gsS0FFSjtBQUFBLENBMU5BOztBQUFhLFFBQUE7OztBQ2JiO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNuQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUM1UUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EiLCJmaWxlIjoiZ2VuZXJhdGVkLmpzIiwic291cmNlUm9vdCI6IiJ9
