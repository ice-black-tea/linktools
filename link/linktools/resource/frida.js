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
    this.$level <= this.debug && send({
      log: {
        level: "debug",
        message: e
      }
    }, r);
  }, e.prototype.i = function(e, r) {
    this.$level <= this.info && send({
      log: {
        level: "info",
        message: e
      }
    }, r);
  }, e.prototype.w = function(e, r) {
    this.$level <= this.warning && send({
      log: {
        level: "warning",
        message: e
      }
    }, r);
  }, e.prototype.e = function(e, r) {
    this.$level <= this.error && send({
      log: {
        level: "error",
        message: e
      }
    }, r);
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
    for (var n = 0, t = e; n < t.length; n++) {
      var o = t[n];
      try {
        (0, eval)(o.source);
      } catch (e) {
        var i = e.hasOwnProperty("stack") ? e.stack : e;
        throw new Error("Unable to load ".concat(o.filename, ": ").concat(i));
      }
    }
  }, e;
}(), n = new r;

rpc.exports = {
  loadScripts: n.load.bind(n)
};

var t = require("./lib/c"), o = require("./lib/java"), i = require("./lib/android"), l = require("./lib/objc"), a = require("./lib/ios"), u = new e, s = new t.CHelper, c = new o.JavaHelper, p = new i.AndroidHelper, f = new l.ObjCHelper, v = new a.IOSHelper;

Object.defineProperties(globalThis, {
  Log: {
    enumerable: !0,
    value: u
  },
  CHelper: {
    enumerable: !0,
    value: s
  },
  JavaHelper: {
    enumerable: !0,
    value: c
  },
  AndroidHelper: {
    enumerable: !0,
    value: p
  },
  ObjCHelper: {
    enumerable: !0,
    value: f
  },
  IOSHelper: {
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
        return u.d("Catch ignored error. " + e), r;
      }
    }
  },
  parseBoolean: {
    enumerable: !1,
    value: function(e, r) {
      if (void 0 === r && (r = void 0), "boolean" == typeof e) return e;
      if ("string" == typeof e) {
        var n = e.toLowerCase();
        if ("true" === n) return !0;
        if ("false" === n) return !1;
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
      if (Array.isArray(e) || c.isArray(e)) {
        for (var r = [], n = 0; n < e.length; n++) r.push(pretty2Json(e[n]));
        return r;
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
    Log.i("======================================================\r\nAndroid Enable Webview Debugging                      \r\n======================================================"), 
    Java.perform((function() {
      var e = "android.webkit.WebView";
      JavaHelper.hookMethods(e, "setWebContentsDebuggingEnabled", (function(e, r) {
        return Log.d("android.webkit.WebView.setWebContentsDebuggingEnabled: " + r[0]), 
        r[0] = !0, this(e, r);
      })), JavaHelper.hookMethods(e, "loadUrl", (function(e, r) {
        return Log.d("android.webkit.WebView.loadUrl: " + r[0]), e.setWebContentsDebuggingEnabled(!0), 
        this(e, r);
      }));
      ignoreError((function() {
        return JavaHelper.hookMethods(e, "setWebContentsDebuggingEnabled", (function(e, r) {
          return Log.d("com.uc.webview.export.WebView.setWebContentsDebuggingEnabled: " + r[0]), 
          r[0] = !0, this(e, r);
        }));
      })), ignoreError((function() {
        return JavaHelper.hookMethods("com.uc.webview.export.WebView", "loadUrl", (function(e, r) {
          return Log.d("com.uc.webview.export.WebView.loadUrl: " + r[0]), e.setWebContentsDebuggingEnabled(!0), 
          this(e, r);
        }));
      }));
    }));
  }, e.prototype.bypassSslPinning = function() {
    Log.i("======================================================\r\nAndroid Bypass ssl pinning                           \r\n======================================================"), 
    Java.perform((function() {
      var e = Java.use("java.util.Arrays");
      ignoreError((function() {
        return JavaHelper.hookMethods("com.android.org.conscrypt.TrustManagerImpl", "checkServerTrusted", (function(r, o) {
          if (Log.d("Bypassing TrustManagerImpl checkServerTrusted"), "void" != this.returnType.type) return "pointer" == this.returnType.type && "java.util.List" == this.returnType.className ? e.asList(o[0]) : void 0;
        }));
      })), ignoreError((function() {
        return JavaHelper.hookMethods("com.google.android.gms.org.conscrypt.Platform", "checkServerTrusted", (function(e, r) {
          Log.d("Bypassing Platform checkServerTrusted {1}");
        }));
      })), ignoreError((function() {
        return JavaHelper.hookMethods("com.android.org.conscrypt.Platform", "checkServerTrusted", (function(e, r) {
          Log.d("Bypassing Platform checkServerTrusted {2}");
        }));
      }));
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
    var i = n;
    Interceptor.replace(a, new NativeCallback((function() {
      for (var t = this, i = [], s = 0; s < n.length; s++) i[s] = arguments[s];
      var c = new Proxy(a, {
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
      return o.call(c, i);
    }), r, i)), Log.i("Hook function: " + e + " (" + a + ")");
  }, t.prototype.getEventImpl = function(t) {
    var e = new function() {
      for (var e in this.method = !0, this.thread = !1, this.stack = !1, this.args = !1, 
      this.extras = {}, t) e in this ? this[e] = t[e] : this.extras[e] = t[e];
    }, r = function(t) {
      var r = {};
      for (var n in e.extras) r[n] = e.extras[n];
      e.method && (r.method_name = this.name), e.thread && (r.thread_id = Process.getCurrentThreadId()), 
      e.args && (r.args = pretty2Json(t), r.result = null, r.error = null);
      try {
        var o = this(t);
        return e.args && (r.result = pretty2Json(o)), o;
      } catch (t) {
        throw e.args && (r.error = pretty2Json(t)), t;
      } finally {
        if (e.stack) {
          for (var a = [], i = Thread.backtrace(this.context, Backtracer.ACCURATE), s = 0; s < i.length; s++) a.push(DebugSymbol.fromAddress(i[s]).toString());
          r.stack = a;
        }
        send({
          event: r
        });
      }
    };
    return r.onLeave = function(t) {
      var r = {};
      for (var n in e.extras) r[n] = e.extras[n];
      if (1 == e.method && (r.method_name = this.name), !0 === e.thread && (r.thread_id = Process.getCurrentThreadId()), 
      !0 === e.args && (r.result = pretty2Json(t)), !0 === e.stack) {
        for (var o = [], a = Thread.backtrace(this.context, Backtracer.ACCURATE), i = 0; i < a.length; i++) o.push(DebugSymbol.fromAddress(a[i]).toString());
        r.stack = o;
      }
      send({
        event: r
      });
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
    Log.i("======================================================\r\niOS Bypass ssl pinning                                \r\n======================================================");
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
      var n = {};
      for (var o in r.extras) n[o] = r.extras[o];
      r.method && (n.class_name = t.$className, n.method_name = this.name, n.method_simple_name = this.methodName), 
      r.thread && (n.thread_id = Process.getCurrentThreadId(), n.thread_name = e.threadClass.currentThread().getName()), 
      r.args && (n.args = pretty2Json(a), n.result = null, n.error = null);
      try {
        var s = this(t, a);
        return r.args && (n.result = pretty2Json(s)), s;
      } catch (t) {
        throw r.args && (n.error = pretty2Json(t)), t;
      } finally {
        r.stack && (n.stack = pretty2Json(e.getStackTrace())), send({
          event: n
        });
      }
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

},{}],6:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.ObjCHelper = void 0;

var t = function() {
  function t() {}
  return t.prototype.$fixMethod = function(t, e) {
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
    void 0 === e && (e = null), null != e ? (t.implementation = ObjC.implement(t, (function() {
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
    this.$fixMethod(n, o), this.$hookMethod(o, r);
  }, t.prototype.hookMethods = function(t, e, r) {
    void 0 === r && (r = null);
    var n = t;
    if ("string" == typeof n && (n = ObjC.classes[n]), void 0 === n) throw Error('cannot find class "' + t + '"');
    for (var o = n.$ownMethods.length, i = 0; i < o; i++) {
      var a = n.$ownMethods[i];
      if (a.indexOf(e) >= 0) {
        var s = n[a];
        this.$fixMethod(n, s), this.$hookMethod(s, r);
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
      if (r.method && (o.class_name = new ObjC.Object(t).$className, o.method_name = this.name, 
      o.method_simple_name = this.methodName), r.thread && (o.thread_id = Process.getCurrentThreadId(), 
      o.thread_name = ObjC.classes.NSThread.currentThread().name().toString()), r.args) {
        for (var a = [], s = 0; s < n.length; s++) a.push(e.convert2ObjcObject(n[s]));
        o.args = pretty2Json(a), o.result = null, o.error = null;
      }
      try {
        var c = this(t, n);
        return r.args && (o.result = pretty2Json(e.convert2ObjcObject(c))), c;
      } catch (t) {
        throw r.args && (o.error = pretty2Json(t)), t;
      } finally {
        if (r.stack) {
          var h = [], l = Thread.backtrace(this.context, Backtracer.ACCURATE);
          for (s = 0; s < l.length; s++) h.push(DebugSymbol.fromAddress(l[s]).toString());
          o.stack = h;
        }
        send({
          event: o
        });
      }
    };
  }, t.prototype.convert2ObjcObject = function(t) {
    return t instanceof NativePointer || "object" == typeof t && t.hasOwnProperty("handle") ? new ObjC.Object(t) : t;
  }, t;
}();

exports.ObjCHelper = t;

},{}]},{},[1])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJpbmRleC50cyIsImxpYi9hbmRyb2lkLnRzIiwibGliL2MudHMiLCJsaWIvaW9zLnRzIiwibGliL2phdmEudHMiLCJsaWIvb2JqYy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7Ozs7OztBQ0tBLElBQUEsSUFBQTtFQUFBLFNBQUE7SUFFSSxLQUFBLFFBQVEsR0FDUixLQUFBLE9BQU8sR0FDUCxLQUFBLFVBQVUsR0FDVixLQUFBLFFBQVEsR0FDQSxLQUFBLFNBQVMsS0FBSzs7RUFrQzFCLE9BaENJLE9BQUEsZUFBSSxFQUFBLFdBQUEsU0FBSztTQUFUO01BQ0ksT0FBTyxLQUFLOzs7O01BR2hCLEVBQUEsVUFBQSxXQUFBLFNBQVM7SUFDTCxLQUFLLFNBQVMsR0FDZCxLQUFLLEVBQUUsb0JBQW9CO0tBRy9CLEVBQUEsVUFBQSxJQUFBLFNBQUUsR0FBYztJQUNSLEtBQUssVUFBVSxLQUFLLFNBQ3BCLEtBQUs7TUFBRSxLQUFLO1FBQUUsT0FBTztRQUFTLFNBQVM7O09BQWE7S0FJNUQsRUFBQSxVQUFBLElBQUEsU0FBRSxHQUFjO0lBQ1IsS0FBSyxVQUFVLEtBQUssUUFDcEIsS0FBSztNQUFFLEtBQUs7UUFBRSxPQUFPO1FBQVEsU0FBUzs7T0FBYTtLQUkzRCxFQUFBLFVBQUEsSUFBQSxTQUFFLEdBQWM7SUFDUixLQUFLLFVBQVUsS0FBSyxXQUNwQixLQUFLO01BQUUsS0FBSztRQUFFLE9BQU87UUFBVyxTQUFTOztPQUFhO0tBSTlELEVBQUEsVUFBQSxJQUFBLFNBQUUsR0FBYztJQUNSLEtBQUssVUFBVSxLQUFLLFNBQ3BCLEtBQUs7TUFBRSxLQUFLO1FBQUUsT0FBTztRQUFTLFNBQVM7O09BQWE7S0FHaEU7Q0F4Q0EsSUF3REEsSUFBQTtFQUFBLFNBQUE7RUFvQkEsT0FsQkksRUFBQSxVQUFBLE9BQUEsU0FBSyxHQUFtQjtJQUNwQixPQUFPLGlCQUFpQixZQUFZO01BQ2hD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QTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUMzTkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSIsImZpbGUiOiJnZW5lcmF0ZWQuanMiLCJzb3VyY2VSb290IjoiIn0=
