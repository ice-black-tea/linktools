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
  return e.prototype.emit = function(e, t, r) {
    var n = {};
    n[e] = t, null == r ? (this.pendingEvents.push(n), this.pendingEvents.length >= 50 ? this.flush() : null === this.flushTimer && (this.flushTimer = setTimeout(this.flush, 50))) : (this.flush(), 
    send({
      $events: [ n ]
    }, r));
  }, e;
}(), t = function() {
  function e() {}
  return e.prototype.emit = function(e, t) {
    f.emit("msg", e, t);
  }, e;
}(), r = function() {
  function e() {
    this.DEBUG = 1, this.INFO = 2, this.WARNING = 3, this.ERROR = 4, this.$level = this.INFO;
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
    this.$level <= this.DEBUG && f.emit("log", {
      level: "debug",
      message: e
    }, t);
  }, e.prototype.i = function(e, t) {
    this.$level <= this.INFO && f.emit("log", {
      level: "info",
      message: e
    }, t);
  }, e.prototype.w = function(e, t) {
    this.$level <= this.WARNING && f.emit("log", {
      level: "warning",
      message: e
    }, t);
  }, e.prototype.e = function(e, t) {
    this.$level <= this.ERROR && f.emit("log", {
      level: "error",
      message: e
    }, t);
  }, e;
}(), n = function() {
  function e() {}
  return e.prototype.load = function(e, t) {
    Object.defineProperties(globalThis, {
      parameters: {
        configurable: !0,
        enumerable: !0,
        value: t
      }
    });
    for (var r = 0, n = e; r < n.length; r++) {
      var i = n[r];
      try {
        (0, eval)(i.source);
      } catch (e) {
        var l = e.hasOwnProperty("stack") ? e.stack : e;
        throw new Error("Unable to load ".concat(i.filename, ": ").concat(l));
      }
    }
  }, e;
}(), i = new n;

rpc.exports = {
  loadScripts: i.load.bind(i)
};

var l = require("./lib/c"), o = require("./lib/java"), u = require("./lib/android"), s = require("./lib/objc"), a = require("./lib/ios"), f = new e, p = new t, v = new r, h = new l.CHelper, c = new o.JavaHelper, g = new u.AndroidHelper, m = new s.ObjCHelper, b = new a.IOSHelper;

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
    value: c
  },
  AndroidHelper: {
    enumerable: !0,
    value: g
  },
  ObjCHelper: {
    enumerable: !0,
    value: m
  },
  IOSHelper: {
    enumerable: !0,
    value: b
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
        var r = e.toLowerCase();
        if ("true" === r) return !0;
        if ("false" === r) return !1;
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
      if (Array.isArray(e) || c.isJavaArray(e)) {
        for (var t = [], r = 0; r < e.length; r++) t.push(pretty2Json(e[r]));
        return t;
      }
      return ignoreError((function() {
        return e.toString();
      }));
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
  }), t.prototype.getExportFunction = function(t, r, e, n) {
    var o = (t || "") + "|" + r;
    if (o in this.$funcCaches) return this.$funcCaches[o];
    var a = Module.findExportByName(t, r);
    if (null === a) throw Error("cannot find " + r);
    return this.$funcCaches[o] = new NativeFunction(a, e, n), this.$funcCaches[o];
  }, t.prototype.hookFunctionWithCallbacks = function(t, r, e) {
    var n = Module.findExportByName(t, r);
    if (null === n) throw Error("cannot find " + r);
    var o = {
      get: function(t, e, n) {
        return "name" === e ? r : t[e];
      }
    }, a = {};
    "onEnter" in e && (a.onEnter = function(t) {
      e.onEnter.call(new Proxy(this, o), t);
    }), "onLeave" in e && (a.onLeave = function(t) {
      e.onLeave.call(new Proxy(this, o), t);
    });
    var i = Interceptor.attach(n, a);
    return Log.i("Hook function: " + r + " (" + n + ")"), i;
  }, t.prototype.hookFunction = function(t, r, e, n, o) {
    var a = this.getExportFunction(t, r, e, n);
    if (null === a) throw Error("cannot find " + r);
    var i = n;
    Interceptor.replace(a, new NativeCallback((function() {
      for (var t = this, i = [], c = 0; c < n.length; c++) i[c] = arguments[c];
      var s = new Proxy(a, {
        get: function(o, a, i) {
          switch (a) {
           case "name":
            return r;

           case "argumentTypes":
            return n;

           case "returnType":
            return e;

           case "context":
            return t.context;

           default:
            o[a];
          }
        },
        apply: function(t, r, e) {
          return t.apply(null, e[0]);
        }
      });
      return o.call(s, i);
    }), e, i)), Log.i("Hook function: " + r + " (" + a + ")");
  }, t.prototype.getEventImpl = function(t) {
    var r = new function() {
      for (var r in this.method = !0, this.thread = !1, this.stack = !1, this.args = !1, 
      this.extras = {}, t) r in this ? this[r] = t[r] : this.extras[r] = t[r];
    }, e = function(t) {
      var e = {};
      for (var n in r.extras) e[n] = r.extras[n];
      !1 !== r.method && (e.method_name = this.name), !1 !== r.thread && (e.thread_id = Process.getCurrentThreadId()), 
      !1 !== r.args && (e.args = pretty2Json(t), e.result = null, e.error = null);
      try {
        var o = this(t);
        return !1 !== r.args && (e.result = pretty2Json(o)), o;
      } catch (t) {
        throw !1 !== r.args && (e.error = pretty2Json(t)), t;
      } finally {
        if (!1 !== r.stack) {
          for (var a = [], i = "fuzzy" !== r.stack ? Backtracer.ACCURATE : Backtracer.FUZZY, c = Thread.backtrace(this.context, i), s = 0; s < c.length; s++) a.push(DebugSymbol.fromAddress(c[s]).toString());
          e.stack = a;
        }
        Emitter.emit(e);
      }
    };
    return e.onLeave = function(t) {
      var e = {};
      for (var n in r.extras) e[n] = r.extras[n];
      if (!1 !== r.method && (e.method_name = this.name), !1 !== r.thread && (e.thread_id = Process.getCurrentThreadId()), 
      !1 !== r.args && (e.result = pretty2Json(t)), !1 !== r.stack) {
        for (var o = [], a = "fuzzy" !== r.stack ? Backtracer.ACCURATE : Backtracer.FUZZY, i = Thread.backtrace(this.context, a), c = 0; c < i.length; c++) o.push(DebugSymbol.fromAddress(i[c]).toString());
        e.stack = o;
      }
      Emitter.emit(e);
    }, e;
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
  return Object.defineProperty(e.prototype, "classClass", {
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
        var s = this.findClass(e, a[o]);
        if (null != s) return s;
      } catch (e) {
        null == r && (r = e);
      }
      throw r;
    }
    var n = Java.classFactory.loader;
    try {
      return Reflect.set(Java.classFactory, "loader", t), Java.use(e);
    } finally {
      Reflect.set(Java.classFactory, "loader", n);
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
      e.implementation = function() {
        return t.call(r, this, Array.prototype.slice.call(arguments));
      }, Log.i("Hook method: " + e);
    } else e.implementation = null, Log.i("Unhook method: " + e);
  }, e.prototype.hookMethod = function(e, t, r, a) {
    void 0 === a && (a = null);
    var o = t;
    if ("string" == typeof o) {
      var s = o, n = e;
      "string" == typeof n && (n = this.findClass(n));
      var i = this.$getClassMethod(n, s);
      if (void 0 === i || void 0 === i.overloads) return void Log.w("Cannot find method: " + this.$getClassName(n) + "." + s);
      if (null != r) {
        var l = r;
        for (var u in l) "string" != typeof l[u] && (l[u] = this.$getClassName(l[u]));
        o = i.overload.apply(i, l);
      } else {
        if (1 != i.overloads.length) throw Error(this.$getClassName(n) + "." + s + " has too many overloads");
        o = i.overloads[0];
      }
    }
    this.$defineMethodProperties(o), this.$hookMethod(o, a);
  }, e.prototype.hookMethods = function(e, t, r) {
    void 0 === r && (r = null);
    var a = e;
    "string" == typeof a && (a = this.findClass(a));
    var o = this.$getClassMethod(a, t);
    if (void 0 !== o && void 0 !== o.overloads) for (var s = 0; s < o.overloads.length; s++) {
      var n = o.overloads[s];
      void 0 !== n.returnType && void 0 !== n.returnType.className && (this.$defineMethodProperties(n), 
      this.$hookMethod(n, r));
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
    for (var a = [], o = null, s = r.class; null != s; ) {
      for (var n = s.getDeclaredMethods(), i = 0; i < n.length; i++) {
        var l = n[i].getName();
        a.indexOf(l) < 0 && (a.push(l), this.hookMethods(r, l, t));
      }
      if (o = s.getSuperclass(), s.$dispose(), null == o) break;
      if (s = Java.cast(o, this.classClass), this.$isExcludeClass(s.getName())) break;
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
      for (var s in r.extras) o[s] = r.extras[s];
      !1 !== r.method && (o.class_name = e.$className, o.method_name = this.name, o.method_simple_name = this.methodName), 
      !1 !== r.thread && (o.thread_id = Process.getCurrentThreadId(), o.thread_name = t.threadClass.currentThread().getName()), 
      !1 !== r.args && (o.args = pretty2Json(a), o.result = null, o.error = null);
      try {
        var n = this(e, a);
        return !1 !== r.args && (o.result = pretty2Json(n)), n;
      } catch (e) {
        throw !1 !== r.args && (o.error = pretty2Json(e)), e;
      } finally {
        !1 !== r.stack && (o.stack = pretty2Json(t.getStackTrace())), Emitter.emit(o);
      }
    };
  }, e.prototype.isJavaArray = function(e) {
    return !!(e.hasOwnProperty("class") && e.class instanceof Object && e.class.hasOwnProperty("isArray") && e.class.isArray());
  }, e.prototype.fromJavaArray = function(e, t) {
    var r = e;
    "string" == typeof r && (r = this.findClass(r));
    for (var a = [], o = Java.vm.getEnv(), s = 0; s < o.getArrayLength(t.$handle); s++) a.push(Java.cast(o.getObjectArrayElement(t.$handle, s), r));
    return a;
  }, e.prototype.getEnumValue = function(e, t) {
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
  return t.prototype.$fixMethod = function(t, e) {
    var r = e.origImplementation || e.implementation, o = t.toString(), n = ObjC.selectorAsString(e.selector), i = ObjC.classes.NSThread.hasOwnProperty(n);
    Object.defineProperties(e, {
      className: {
        configurable: !0,
        enumerable: !0,
        get: function() {
          return o;
        }
      },
      methodName: {
        configurable: !0,
        enumerable: !0,
        get: function() {
          return n;
        }
      },
      name: {
        configurable: !0,
        enumerable: !0,
        get: function() {
          return (i ? "+" : "-") + "[" + o + " " + n + "]";
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
    void 0 === e && (e = null), null != e ? (t.implementation = ObjC.implement(t, (function() {
      var r = this, o = Array.prototype.slice.call(arguments), n = o.shift(), i = o.shift(), a = new Proxy(t, {
        get: function(t, e, o) {
          return e in r ? r[e] : t[e];
        },
        apply: function(t, e, r) {
          var o = r[0], n = r[1];
          return t.origImplementation.apply(null, [].concat(o, i, n));
        }
      });
      return e.call(a, n, o);
    })), Log.i("Hook method: " + t)) : (t.implementation = t.origImplementation, Log.i("Unhook method: " + pretty2String(t)));
  }, t.prototype.hookMethod = function(t, e, r) {
    void 0 === r && (r = null);
    var o = t;
    if ("string" == typeof o && (o = ObjC.classes[o]), void 0 === o) throw Error('cannot find class "' + t + '"');
    var n = e;
    if ("string" == typeof n && (n = o[n]), void 0 === n) throw Error('cannot find method "' + e + '" in class "' + o + '"');
    this.$fixMethod(o, n), this.$hookMethod(n, r);
  }, t.prototype.hookMethods = function(t, e, r) {
    void 0 === r && (r = null);
    var o = t;
    if ("string" == typeof o && (o = ObjC.classes[o]), void 0 === o) throw Error('cannot find class "' + t + '"');
    for (var n = o.$ownMethods.length, i = 0; i < n; i++) {
      var a = o.$ownMethods[i];
      if (a.indexOf(e) >= 0) {
        var s = o[a];
        this.$fixMethod(o, s), this.$hookMethod(s, r);
      }
    }
  }, t.prototype.getEventImpl = function(t) {
    var e = this, r = new function() {
      for (var e in this.method = !0, this.thread = !1, this.stack = !1, this.args = !1, 
      this.extras = {}, t) e in this ? this[e] = t[e] : this.extras[e] = t[e];
    };
    return function(t, o) {
      var n = {};
      for (var i in r.extras) n[i] = r.extras[i];
      if (!1 !== r.method && (n.class_name = new ObjC.Object(t).$className, n.method_name = this.name, 
      n.method_simple_name = this.methodName), !1 !== r.thread && (n.thread_id = Process.getCurrentThreadId(), 
      n.thread_name = ObjC.classes.NSThread.currentThread().name().toString()), !1 !== r.args) {
        for (var a = [], s = 0; s < o.length; s++) a.push(e.convert2ObjcObject(o[s]));
        n.args = pretty2Json(a), n.result = null, n.error = null;
      }
      try {
        var c = this(t, o);
        return !1 !== r.args && (n.result = pretty2Json(e.convert2ObjcObject(c))), c;
      } catch (t) {
        throw !1 !== r.args && (n.error = pretty2Json(t)), t;
      } finally {
        if (!1 !== r.stack) {
          var h = [], l = "fuzzy" !== r.stack ? Backtracer.ACCURATE : Backtracer.FUZZY, u = Thread.backtrace(this.context, l);
          for (s = 0; s < u.length; s++) h.push(DebugSymbol.fromAddress(u[s]).toString());
          n.stack = h;
        }
        Emitter.emit(n);
      }
    };
  }, t.prototype.convert2ObjcObject = function(t) {
    return t instanceof NativePointer || "object" == typeof t && t.hasOwnProperty("handle") ? new ObjC.Object(t) : t;
  }, t;
}();

exports.ObjCHelper = t;

},{}]},{},[1])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJpbmRleC50cyIsImxpYi9hbmRyb2lkLnRzIiwibGliL2MudHMiLCJsaWIvaW9zLnRzIiwibGliL2phdmEudHMiLCJsaWIvb2JqYy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7Ozs7OztBQ0tBLElBQUEsSUFBQTtFQUFBLFNBQUE7SUFBQSxJQUFBLElBQUE7SUFFWSxLQUFBLGdCQUF1QixJQUN2QixLQUFBLGFBQWtCLE1Bd0JsQixLQUFBLFFBQVE7TUFNWixJQUx3QixTQUFwQixFQUFLLGVBQ0wsYUFBYSxFQUFLLGFBQ2xCLEVBQUssYUFBYTtNQUdZLE1BQTlCLEVBQUssY0FBYyxRQUF2QjtRQUlBLElBQU0sSUFBUyxFQUFLO1FBQ3BCLEVBQUssZ0JBQWdCLElBRXJCLEtBQUs7VUFBRSxTQUFTOzs7QUFDcEI7QUFDSjtFQUFBLE9BckNJLEVBQUEsVUFBQSxPQUFBLFNBQUssR0FBYyxHQUFjO0lBQzdCLElBQU0sSUFBUTtJQUNkLEVBQU0sS0FBUSxHQUVGLFFBQVIsS0FFQSxLQUFLLGNBQWMsS0FBSyxJQUNwQixLQUFLLGNBQWMsVUFBVSxLQUc3QixLQUFLLFVBQ3NCLFNBQXBCLEtBQUssZUFDWixLQUFLLGFBQWEsV0FBVyxLQUFLLE9BQU8sU0FLN0MsS0FBSztJQUNMLEtBQUs7TUFBRSxTQUFTLEVBQUM7T0FBVTtBQUVuQyxLQWlCSjtBQUFBLENBMUNBLElBNkNBLElBQUE7RUFBQSxTQUFBLEtBS0E7RUFBQSxPQUhJLEVBQUEsVUFBQSxPQUFBLFNBQUssR0FBYztJQUNmLEVBQWMsS0FBSyxPQUFPLEdBQVM7QUFDdkMsS0FDSjtBQUFBLENBTEEsSUFZQSxJQUFBO0VBQUEsU0FBQTtJQUVJLEtBQUEsUUFBUSxHQUNSLEtBQUEsT0FBTyxHQUNQLEtBQUEsVUFBVSxHQUNWLEtBQUEsUUFBUSxHQUNBLEtBQUEsU0FBUyxLQUFLO0FBa0MxQjtFQUFBLE9BaENJLE9BQUEsZUFB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QTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQ3hHQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDbkNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNB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
