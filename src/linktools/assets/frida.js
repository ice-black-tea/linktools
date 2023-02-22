(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
});

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
        for (var t = "", n = 0; n < arguments.length; n++) n > 0 && (t += " "), t += arguments[n];
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
    Object.defineProperties(globalThis, {
      parameters: {
        configurable: !0,
        enumerable: !0,
        value: t
      }
    });
    for (var n = 0, r = e; n < r.length; n++) {
      var i = r[n];
      try {
        (0, eval)(i.source);
      } catch (e) {
        var o = e.hasOwnProperty("stack") ? e.stack : e;
        throw new Error("Unable to load ".concat(i.filename, ": ").concat(o));
      }
    }
  }, e;
}(), i = new r, o = new e, l = {};

rpc.exports = {
  loadScripts: i.load.bind(i)
};

var u = require("./lib/c"), s = require("./lib/java"), a = require("./lib/android"), c = require("./lib/objc"), f = require("./lib/ios"), h = new t, v = new n, p = new u.CHelper, b = new s.JavaHelper, d = new a.AndroidHelper, g = new c.ObjCHelper, m = new f.IOSHelper;

Object.defineProperties(globalThis, {
  Emitter: {
    enumerable: !0,
    value: h
  },
  Log: {
    enumerable: !0,
    value: v
  },
  CHelper: {
    enumerable: !0,
    value: p
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
  function e() {}
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
        return JavaHelper.hookMethods("com.android.org.conscrypt.TrustManagerImpl", "checkServerTrusted", (function(o, r) {
          if (Log.d("Bypassing TrustManagerImpl checkServerTrusted"), "void" != this.returnType.type) return "pointer" == this.returnType.type && "java.util.List" == this.returnType.className ? e.asList(r[0]) : void 0;
        }));
      })), ignoreError((function() {
        return JavaHelper.hookMethods("com.google.android.gms.org.conscrypt.Platform", "checkServerTrusted", (function(e, o) {
          Log.d("Bypassing Platform checkServerTrusted {1}");
        }));
      })), ignoreError((function() {
        return JavaHelper.hookMethods("com.android.org.conscrypt.Platform", "checkServerTrusted", (function(e, o) {
          Log.d("Bypassing Platform checkServerTrusted {2}");
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
  }, e.prototype.traceClasses = function(e, o, r) {
    void 0 === o && (o = void 0), void 0 === r && (r = void 0), e = null != e ? e.trim().toLowerCase() : "", 
    o = null != o ? o.trim().toLowerCase() : "", r = null != r ? r : {
      stack: !0,
      args: !0
    }, Log.w("trace classes, include: " + e + ", exclude: " + o + ", options: " + JSON.stringify(r)), 
    Java.perform((function() {
      Java.enumerateLoadedClasses({
        onMatch: function(t) {
          var n = t.toString().toLowerCase();
          n.indexOf(e) >= 0 && ("" == o || n.indexOf(o) < 0) && JavaHelper.hookAllMethods(t, JavaHelper.getEventImpl(r));
        },
        onComplete: function() {
          Log.d("enumerate classLoaders complete");
        }
      });
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
  }), e.prototype.findClass = function(e, t) {
    if (void 0 === t && (t = void 0), void 0 === t || null == t) {
      if (parseInt(Java.androidVersion) < 7) return Java.use(e);
      var r = null, a = Java.enumerateClassLoadersSync();
      for (var o in a) try {
        var n = this.findClass(e, a[o]);
        if (null != n) return n;
      } catch (e) {
        null == r && (r = e);
      }
      throw r;
    }
    var s = Java.classFactory.loader;
    try {
      return Reflect.set(Java.classFactory, "loader", t), Java.use(e);
    } finally {
      Reflect.set(Java.classFactory, "loader", s);
    }
  }, e.prototype.$getClassName = function(e) {
    var t = e.$className;
    if (null != t) return t;
    if (null != (t = e.__name__)) return t;
    if (null != e.$classWrapper) {
      if (null != (t = e.$classWrapper.$className)) return t;
      if (null != (t = e.$classWrapper.__name__)) return t;
    }
    Log.e("Cannot get class name: " + e);
  }, e.prototype.$getClassMethod = function(e, t) {
    var r = e[t];
    return void 0 !== r || "$" == t[0] && void 0 !== (r = e["_" + t]) ? r : void 0;
  }, e.prototype.$defineMethodProperties = function(e) {
    Object.defineProperties(e, {
      className: {
        configurable: !0,
        enumerable: !0,
        writable: !1,
        value: this.$getClassName(e.holder)
      },
      name: {
        configurable: !0,
        enumerable: !0,
        get: function() {
          var e = this.returnType.className, t = this.className + "." + this.methodName, r = "";
          if (this.argumentTypes.length > 0) {
            r = this.argumentTypes[0].className;
            for (var a = 1; a < this.argumentTypes.length; a++) r = r + ", " + this.argumentTypes[a].className;
          }
          return e + " " + t + "(" + r + ")";
        }
      },
      toString: {
        configurable: !0,
        value: function() {
          return this.name;
        }
      }
    });
  }, e.prototype.$hookMethod = function(e, t) {
    if (void 0 === t && (t = null), null != t) {
      var r = new Proxy(e, {
        apply: function(e, t, r) {
          var a = r[0], o = r[1];
          return e.apply(a, o);
        }
      });
      isFunction(t) || (t = this.getEventImpl(t)), e.implementation = function() {
        return t.call(r, this, Array.prototype.slice.call(arguments));
      }, Log.i("Hook method: " + e);
    } else e.implementation = null, Log.i("Unhook method: " + e);
  }, e.prototype.hookMethod = function(e, t, r, a) {
    void 0 === a && (a = null);
    var o = t;
    if ("string" == typeof o) {
      var n = o, s = e;
      "string" == typeof s && (s = this.findClass(s));
      var i = this.$getClassMethod(s, n);
      if (void 0 === i || void 0 === i.overloads) return void Log.w("Cannot find method: " + this.$getClassName(s) + "." + n);
      if (null != r) {
        var l = r;
        for (var u in l) "string" != typeof l[u] && (l[u] = this.$getClassName(l[u]));
        o = i.overload.apply(i, l);
      } else {
        if (1 != i.overloads.length) throw Error(this.$getClassName(s) + "." + n + " has too many overloads");
        o = i.overloads[0];
      }
    }
    this.$defineMethodProperties(o), this.$hookMethod(o, a);
  }, e.prototype.hookMethods = function(e, t, r) {
    void 0 === r && (r = null);
    var a = e;
    "string" == typeof a && (a = this.findClass(a));
    var o = this.$getClassMethod(a, t);
    if (void 0 !== o && void 0 !== o.overloads) for (var n = 0; n < o.overloads.length; n++) {
      var s = o.overloads[n];
      void 0 !== s.returnType && void 0 !== s.returnType.className && (this.$defineMethodProperties(s), 
      this.$hookMethod(s, r));
    } else Log.w("Cannot find method: " + this.$getClassName(a) + "." + t);
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
    for (var a = [], o = null, n = r.class; null != n; ) {
      for (var s = n.getDeclaredMethods(), i = 0; i < s.length; i++) {
        var l = s[i].getName();
        a.indexOf(l) < 0 && (a.push(l), this.hookMethods(r, l, t));
      }
      if (o = n.getSuperclass(), n.$dispose(), null == o) break;
      if (n = Java.cast(o, this.classClass), this.$isExcludeClass(n.getName())) break;
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
      var o = {};
      for (var n in r.extras) o[n] = r.extras[n];
      !1 !== r.method && (o.class_name = e.$className, o.method_name = this.name, o.method_simple_name = this.methodName), 
      !1 !== r.thread && (o.thread_id = Process.getCurrentThreadId(), o.thread_name = t.threadClass.currentThread().getName()), 
      !1 !== r.args && (o.args = pretty2Json(a), o.result = null, o.error = null);
      try {
        var s = this(e, a);
        return !1 !== r.args && (o.result = pretty2Json(s)), s;
      } catch (e) {
        throw !1 !== r.args && (o.error = pretty2Json(e)), e;
      } finally {
        !1 !== r.stack && (o.stack = pretty2Json(t.getStackTrace())), Emitter.emit(o);
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
    for (var a = [], o = Java.vm.getEnv(), n = 0; n < o.getArrayLength(t.$handle); n++) a.push(Java.cast(o.getObjectArrayElement(t.$handle, n), r));
    return a;
  }, e.prototype.getJavaEnumValue = function(e, t) {
    var r = e;
    "string" == typeof r && (r = this.findClass(r));
    var a = r.class.getEnumConstants();
    a instanceof Array || (a = this.fromJavaArray(r, a));
    for (var o = 0; o < a.length; o++) if (a[o].toString() === t) return a[o];
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJpbmRleC50cyIsImxpYi9hbmRyb2lkLnRzIiwibGliL2MudHMiLCJsaWIvaW9zLnRzIiwibGliL2phdmEudHMiLCJsaWIvb2JqYy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7Ozs7OztBQ0tBLElBQUEsSUFBQTtFQUFBLFNBQUE7SUFBQSxJQUFBLElBQUE7SUFFWSxLQUFBLGdCQUF1QixJQUN2QixLQUFBLGFBQWtCLE1Bd0JsQixLQUFBLFFBQVE7TUFNWixJQUx3QixTQUFwQixFQUFLLGVBQ0wsYUFBYSxFQUFLLGFBQ2xCLEVBQUssYUFBYTtNQUdZLE1BQTlCLEVBQUssY0FBYyxRQUF2QjtRQUlBLElBQU0sSUFBUyxFQUFLO1FBQ3BCLEVBQUssZ0JBQWdCLElBRXJCLEtBQUs7VUFBRSxTQUFTOzs7QUFDcEI7QUFDSjtFQUFBLE9BckNJLEVBQUEsVUFBQSxPQUFBLFNBQUssR0FBYyxHQUFjO0lBQzdCLElBQU0sSUFBUTtJQUNkLEVBQU0sS0FBUSxHQUVGLFFBQVIsS0FFQSxLQUFLLGNBQWMsS0FBSyxJQUNwQixLQUFLLGNBQWMsVUFBVSxLQUc3QixLQUFLLFVBQ3NCLFNBQXBCLEtBQUssZUFDWixLQUFLLGFBQWEsV0FBVyxLQUFLLE9BQU8sU0FLN0MsS0FBSztJQUNMLEtBQUs7TUFBRSxTQUFTLEVBQUM7T0FBVTtBQUVuQyxLQWlCSjtBQUFBLENBMUNBLElBNkNBLElBQUE7RUFBQSxTQUFBLEtBS0E7RUFBQSxPQUhJLEVBQUEsVUFBQSxPQUFBLFNBQUssR0FBYztJQUNmLEVBQWMsS0FBSyxPQUFPLEdBQVM7QUFDdkMsS0FDSjtBQUFBLENBTEEsSUFZQSxJQUFBO0VBUUksU0FBQTtJQU5BLEtBQUEsUUFBUSxHQUNSLEtBQUEsT0FBTyxHQUNQLEtBQUEsVUFBVSxHQUNWLEtBQUEsUUFBUSxHQUNBLEtBQUEsU0FBUyxLQUFLO0lBR2xCLElBQU0sSUFBVyxTQUFXO01BQ3hC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QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ25GQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDM0dBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUNuQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNB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
