(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
(function (global){(function (){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.ScriptLoader = void 0;

var e = require("./lib/log"), r = require("./lib/c"), n = require("./lib/java"), t = require("./lib/objc"), o = function(e) {
  return function() {
    if (arguments.length > 0) {
      for (var r = pretty2String(arguments[0]), n = 1; n < arguments.length; n++) r += " ", 
      r += pretty2String(arguments[n]);
      e(r);
    } else e("");
  };
};

console.debug = o(e.d.bind(e)), console.info = o(e.i.bind(e)), console.warn = o(e.w.bind(e)), 
console.error = o(e.e.bind(e)), console.log = o(e.i.bind(e)), null != global._setUnhandledExceptionCallback && global._setUnhandledExceptionCallback((function(r) {
  var t = void 0;
  if (r instanceof Error) {
    var o = r.stack;
    void 0 !== o && (t = o);
  }
  if (Java.available) {
    var a = n.getErrorStack(r);
    void 0 !== a && (void 0 !== t ? t += "\n\nCaused by: \n".concat(a) : t = a);
  }
  e.exception("" + r, t);
}));

var a = function() {
  function e() {}
  return e.prototype.load = function(e, r) {
    for (var n = 0, t = e; n < t.length; n++) {
      var o = t[n];
      try {
        var a = o.filename;
        a = (a = a.replace(/[\/\\]/g, "$")).replace(/[^A-Za-z0-9_$]+/g, "_"), a = "fn_".concat(a).substring(0, 255), 
        (0, eval)("(function ".concat(a, "(parameters) {").concat(o.source, "\n})\n") + "//# sourceURL=".concat(o.filename))(r);
      } catch (e) {
        var i = e.hasOwnProperty("stack") ? e.stack : e;
        throw new Error("Unable to load ".concat(o.filename, ": ").concat(i));
      }
    }
  }, e;
}();

exports.ScriptLoader = a;

var i = new a;

rpc.exports = {
  loadScripts: i.load.bind(i)
}, Object.defineProperties(globalThis, {
  Log: {
    enumerable: !0,
    value: e
  },
  CHelper: {
    enumerable: !0,
    value: r
  },
  JavaHelper: {
    enumerable: !0,
    value: n
  },
  ObjCHelper: {
    enumerable: !0,
    value: t
  },
  isFunction: {
    enumerable: !1,
    value: function(e) {
      return "[object Function]" === Object.prototype.toString.call(e);
    }
  },
  ignoreError: {
    enumerable: !1,
    value: function(r, n) {
      void 0 === n && (n = void 0);
      try {
        return r();
      } catch (r) {
        return e.d("Catch ignored error. " + r), n;
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
      return "string" != typeof e && (e = pretty2Json(e)), JSON.stringify(e);
    }
  },
  pretty2Json: {
    enumerable: !1,
    value: function(e) {
      if (!(e instanceof Object)) return e;
      if (Array.isArray(e)) {
        for (var r = [], t = 0; t < e.length; t++) r.push(pretty2Json(e[t]));
        return r;
      }
      return Java.available && n.isJavaObject(e) ? n.o.objectClass.toString.apply(e) : ignoreError((function() {
        return e.toString();
      }));
    }
  }
});

}).call(this)}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})

},{"./lib/c":2,"./lib/java":3,"./lib/log":4,"./lib/objc":5}],2:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.getDebugSymbolFromAddress = exports.getEventImpl = exports.hookFunction = exports.hookFunctionWithCallbacks = exports.hookFunctionWithOptions = exports.getExportFunction = void 0;

var t = require("./log"), r = function() {
  function t() {}
  return Object.defineProperty(t.prototype, "dlopen", {
    get: function() {
      return a(null, "dlopen", "pointer", [ "pointer", "int" ]);
    },
    enumerable: !1,
    configurable: !0
  }), t;
}(), e = new r, n = {}, o = {};

function a(t, r, e, o) {
  var a = (t || "") + "|" + r;
  if (a in n) return n[a];
  var i = Module.findExportByName(t, r);
  if (null === i) throw Error("cannot find " + r);
  return n[a] = new NativeFunction(i, e, o), n[a];
}

function i(t, r, e) {
  return s(t, r, u(e));
}

function s(r, e, n) {
  var o = Module.findExportByName(r, e);
  if (null === o) throw Error("cannot find " + e);
  var a = {
    get: function(t, r, n) {
      return "name" === r ? e : t[r];
    }
  }, i = {};
  "onEnter" in n && (i.onEnter = function(t) {
    n.onEnter.call(new Proxy(this, a), t);
  }), "onLeave" in n && (i.onLeave = function(t) {
    n.onLeave.call(new Proxy(this, a), t);
  });
  var s = Interceptor.attach(o, i);
  return t.i("Hook function: " + e + " (" + o + ")"), s;
}

function c(r, e, n, o, i) {
  var s = a(r, e, n, o);
  if (null === s) throw Error("cannot find " + e);
  isFunction(i) || (i = u(i));
  var c = o;
  Interceptor.replace(s, new NativeCallback((function() {
    for (var t = this, r = [], a = 0; a < o.length; a++) r[a] = arguments[a];
    var c = new Proxy(s, {
      get: function(r, a, i) {
        switch (a) {
         case "name":
          return e;

         case "argumentTypes":
          return o;

         case "returnType":
          return n;

         case "context":
          return t.context;

         default:
          r[a];
        }
      },
      apply: function(t, r, e) {
        return t.apply(null, e[0]);
      }
    });
    return i.call(c, r);
  }), n, c)), t.i("Hook function: " + e + " (" + s + ")");
}

function u(r) {
  var e = new function() {
    for (var t in this.method = !0, this.thread = !1, this.stack = !1, this.args = !1, 
    this.extras = {}, r) t in this ? this[t] = r[t] : this.extras[t] = r[t];
  }, n = function(r) {
    var n = {};
    for (var o in e.extras) n[o] = e.extras[o];
    !1 !== e.method && (n.method_name = this.name), !1 !== e.thread && (n.thread_id = Process.getCurrentThreadId()), 
    !1 !== e.args && (n.args = pretty2Json(r), n.result = null, n.error = null);
    try {
      var a = this(r);
      return !1 !== e.args && (n.result = pretty2Json(a)), a;
    } catch (t) {
      throw !1 !== e.args && (n.error = pretty2Json(t)), t;
    } finally {
      if (!1 !== e.stack) {
        for (var i = [], s = "fuzzy" !== e.stack ? Backtracer.ACCURATE : Backtracer.FUZZY, c = Thread.backtrace(this.context, s), u = 0; u < c.length; u++) i.push(h(c[u]).toString());
        n.stack = i;
      }
      t.event(n);
    }
  };
  return n.onLeave = function(r) {
    var n = {};
    for (var o in e.extras) n[o] = e.extras[o];
    if (!1 !== e.method && (n.method_name = this.name), !1 !== e.thread && (n.thread_id = Process.getCurrentThreadId()), 
    !1 !== e.args && (n.result = pretty2Json(r)), !1 !== e.stack) {
      for (var a = [], i = "fuzzy" !== e.stack ? Backtracer.ACCURATE : Backtracer.FUZZY, s = Thread.backtrace(this.context, i), c = 0; c < s.length; c++) a.push(h(s[c]).toString());
      n.stack = a;
    }
    t.event(n);
  }, n;
}

function h(t) {
  var r = t.toString();
  return void 0 === o[r] && (o[r] = DebugSymbol.fromAddress(t)), o[r];
}

exports.getExportFunction = a, exports.hookFunctionWithOptions = i, exports.hookFunctionWithCallbacks = s, 
exports.hookFunction = c, exports.getEventImpl = u, exports.getDebugSymbolFromAddress = h;

},{"./log":4}],3:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.getErrorStack = exports.runOnCreateApplication = exports.runOnCreateContext = exports.traceClasses = exports.chooseClassLoader = exports.bypassSslPinning = exports.setWebviewDebuggingEnabled = exports.use = exports.getStackTrace = exports.getJavaEnumValue = exports.fromJavaArray = exports.isJavaArray = exports.isJavaObject = exports.getEventImpl = exports.hookClass = exports.hookAllMethods = exports.hookAllConstructors = exports.hookMethods = exports.hookMethod = exports.findClass = exports.getClassMethod = exports.getClassName = exports.getObjectHandle = exports.isSameObject = exports.o = void 0;

var e = require("./log"), t = function() {
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
  }), Object.defineProperty(e.prototype, "classLoaderClass", {
    get: function() {
      return Java.use("java.lang.ClassLoader");
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
  }), Object.defineProperty(e.prototype, "hashSetClass", {
    get: function() {
      return Java.use("java.util.HashSet");
    },
    enumerable: !1,
    configurable: !0
  }), Object.defineProperty(e.prototype, "applicationContext", {
    get: function() {
      return Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
    },
    enumerable: !1,
    configurable: !0
  }), e;
}();

function r(e, t) {
  return e === t || null != e && null != t && (!!e.hasOwnProperty("$isSameObject") && e.$isSameObject(t));
}

function n(e) {
  return null == e ? null : e.hasOwnProperty("$h") ? e.$h : void 0;
}

function a(t) {
  var r = t.$className;
  if (null != r) return r;
  if (null != (r = t.__name__)) return r;
  if (null != t.$classWrapper) {
    if (null != (r = t.$classWrapper.$className)) return r;
    if (null != (r = t.$classWrapper.__name__)) return r;
  }
  e.e("Cannot get class name: " + t);
}

function o(e, t) {
  var r = e[t];
  return void 0 !== r || "$" == t[0] && void 0 !== (r = e["_" + t]) ? r : void 0;
}

function s(e, t) {
  if (void 0 === t && (t = void 0), void 0 !== t && null != t) return Java.ClassFactory.get(t).use(e);
  if (parseInt(Java.androidVersion) < 7) return Java.use(e);
  for (var r = null, n = 0, a = Java.enumerateClassLoadersSync(); n < a.length; n++) {
    var o = a[n];
    try {
      var i = s(e, o);
      if (null != i) return i;
    } catch (e) {
      null == r && (r = e);
    }
  }
  throw r;
}

function i(e, t, r, n) {
  void 0 === n && (n = null);
  var i = t;
  if ("string" == typeof i) {
    var l = i, c = e;
    "string" == typeof c && (c = s(c));
    var u = o(c, l);
    if (void 0 === u || void 0 === u.overloads) throw Error("Cannot find method: " + a(c) + "." + l);
    if (null != r) {
      var p = r;
      for (var d in p) "string" != typeof p[d] && (p[d] = a(p[d]));
      i = u.overload.apply(u, p);
    } else {
      if (1 != u.overloads.length) throw Error(a(c) + "." + l + " has too many overloads");
      i = u.overloads[0];
    }
  }
  P(i), E(i, n);
}

function l(e, t, r) {
  void 0 === r && (r = null);
  var n = e;
  "string" == typeof n && (n = s(n));
  var i = o(n, t);
  if (void 0 === i || void 0 === i.overloads) throw Error("Cannot find method: " + a(n) + "." + t);
  for (var l = 0; l < i.overloads.length; l++) {
    var c = i.overloads[l];
    void 0 !== c.returnType && void 0 !== c.returnType.className && (P(c), E(c, r));
  }
}

function c(e, t) {
  void 0 === t && (t = null);
  var r = e;
  "string" == typeof r && (r = s(r)), l(r, "$init", t);
}

function u(e, t) {
  void 0 === t && (t = null);
  var r = e;
  "string" == typeof r && (r = s(r));
  for (var n = [], a = null, o = r.class; null != o; ) {
    for (var i = o.getDeclaredMethods(), c = 0; c < i.length; c++) {
      var u = i[c].getName();
      n.indexOf(u) < 0 && (n.push(u), l(r, u, t));
    }
    if (a = o.getSuperclass(), o.$dispose(), null == a) break;
    if (L((o = Java.cast(a, exports.o.classClass)).getName())) break;
  }
}

function p(e, t) {
  void 0 === t && (t = null);
  var r = e;
  "string" == typeof r && (r = s(r)), c(r, t), u(r, t);
}

function d(t) {
  var r = new function() {
    for (var e in this.method = !0, this.thread = !1, this.stack = !1, this.args = !1, 
    this.extras = {}, t) e in this ? this[e] = t[e] : this.extras[e] = t[e];
  };
  return function(t, n) {
    var a = {};
    for (var o in r.extras) a[o] = r.extras[o];
    !1 !== r.method && (a.class_name = t.$className, a.method_name = this.name, a.method_simple_name = this.methodName), 
    !1 !== r.thread && (a.thread_id = Process.getCurrentThreadId(), a.thread_name = exports.o.threadClass.currentThread().getName()), 
    !1 !== r.args && (a.args = pretty2Json(n), a.result = null, a.error = null);
    try {
      var s = this(t, n);
      return !1 !== r.args && (a.result = pretty2Json(s)), s;
    } catch (e) {
      throw !1 !== r.args && (a.error = pretty2Json(e)), e;
    } finally {
      !1 !== r.stack && (a.stack = pretty2Json(b())), e.event(a);
    }
  };
}

function f(e) {
  if (e instanceof Object && e.hasOwnProperty("class") && e.class instanceof Object) {
    var t = e.class;
    if (t.hasOwnProperty("getName") && t.hasOwnProperty("getDeclaredClasses") && t.hasOwnProperty("getDeclaredFields") && t.hasOwnProperty("getDeclaredMethods")) return !0;
  }
  return !1;
}

function g(e) {
  if (e instanceof Object && e.hasOwnProperty("class") && e.class instanceof Object) {
    var t = e.class;
    if (t.hasOwnProperty("isArray") && t.isArray()) return !0;
  }
  return !1;
}

function h(e, t) {
  var r = e;
  "string" == typeof r && (r = s(r));
  for (var n = [], a = Java.vm.getEnv(), o = 0; o < a.getArrayLength(t.$handle); o++) n.push(Java.cast(a.getObjectArrayElement(t.$handle, o), r));
  return n;
}

function v(e, t) {
  var r = e;
  "string" == typeof r && (r = s(r));
  var n = r.class.getEnumConstants();
  n instanceof Array || (n = h(r, n));
  for (var a = 0; a < n.length; a++) if (n[a].toString() === t) return n[a];
  throw new Error("Name of " + t + " does not match " + r);
}

function b(e) {
  void 0 === e && (e = void 0);
  for (var t = [], r = (e || exports.o.throwableClass.$new()).getStackTrace(), n = 0; n < r.length; n++) t.push(r[n]);
  return t;
}

exports.o = new t, exports.isSameObject = r, exports.getObjectHandle = n, exports.getClassName = a, 
exports.getClassMethod = o, exports.findClass = s, exports.hookMethod = i, exports.hookMethods = l, 
exports.hookAllConstructors = c, exports.hookAllMethods = u, exports.hookClass = p, 
exports.getEventImpl = d, exports.isJavaObject = f, exports.isJavaArray = g, exports.fromJavaArray = h, 
exports.getJavaEnumValue = v, exports.getStackTrace = b;

var y = null;

function m(t) {
  var r = exports.o.hashSetClass.$new(), n = function(r) {
    for (var n, a = t.entries(), o = function() {
      var a = n.value[0], o = n.value[1], i = null;
      try {
        i = s(a, r);
      } catch (e) {}
      null != i && (t.delete(a), o.forEach((function(t, r, n) {
        try {
          t(i);
        } catch (t) {
          e.w("Call JavaHelper.use callback error: " + t);
        }
      })));
    }; !(n = a.next()).done; ) o();
  }, a = exports.o.classClass, o = exports.o.classLoaderClass;
  i(a, "forName", [ "java.lang.String", "boolean", o ], (function(e, t) {
    var a = t[2];
    return null == a || r.contains(a) || (r.add(a), n(a)), this(e, t);
  })), i(o, "loadClass", [ "java.lang.String", "boolean" ], (function(e, t) {
    var a = e;
    return r.contains(a) || (r.add(a), n(a)), this(e, t);
  }));
}

function x(t, r) {
  var n = null;
  try {
    n = s(t);
  } catch (e) {
    var a;
    if (null == y && m(y = new Map), y.has(t)) void 0 !== (a = y.get(t)) && a.add(r); else (a = new Set).add(r), 
    y.set(t, a);
    return;
  }
  try {
    r(n);
  } catch (t) {
    e.w("Call JavaHelper.use callback error: " + t);
  }
}

function C() {
  e.w("Android Enable Webview Debugging"), ignoreError((function() {
    var t = s("android.webkit.WebView");
    l(t, "setWebContentsDebuggingEnabled", (function(r, n) {
      return e.d("".concat(t, ".setWebContentsDebuggingEnabled: ").concat(n[0])), n[0] = !0, 
      this(r, n);
    })), l(t, "loadUrl", (function(r, n) {
      return e.d("".concat(t, ".loadUrl: ").concat(n[0])), t.setWebContentsDebuggingEnabled(!0), 
      this(r, n);
    }));
  })), ignoreError((function() {
    var t = s("com.uc.webview.export.WebView");
    l(t, "setWebContentsDebuggingEnabled", (function(r, n) {
      return e.d("".concat(t, ".setWebContentsDebuggingEnabled: ").concat(n[0])), n[0] = !0, 
      this(r, n);
    })), l(t, "loadUrl", (function(r, n) {
      return e.d("".concat(t, ".loadUrl: ").concat(n[0])), t.setWebContentsDebuggingEnabled(!0), 
      this(r, n);
    }));
  }));
}

function k() {
  e.w("Android Bypass ssl pinning");
  var t = Java.use("java.util.Arrays");
  ignoreError((function() {
    return l("com.android.org.conscrypt.TrustManagerImpl", "checkServerTrusted", (function(r, n) {
      if (e.d("SSL bypassing " + this), "void" != this.returnType.type) return "pointer" == this.returnType.type && "java.util.List" == this.returnType.className ? t.asList(n[0]) : void 0;
    }));
  })), ignoreError((function() {
    return l("com.google.android.gms.org.conscrypt.Platform", "checkServerTrusted", (function(t, r) {
      e.d("SSL bypassing " + this);
    }));
  })), ignoreError((function() {
    return l("com.android.org.conscrypt.Platform", "checkServerTrusted", (function(t, r) {
      e.d("SSL bypassing " + this);
    }));
  })), ignoreError((function() {
    return l("okhttp3.CertificatePinner", "check", (function(t, r) {
      if (e.d("SSL bypassing " + this), "boolean" == this.returnType.type) return !0;
    }));
  })), ignoreError((function() {
    return l("okhttp3.CertificatePinner", "check$okhttp", (function(t, r) {
      e.d("SSL bypassing " + this);
    }));
  })), ignoreError((function() {
    return l("com.android.okhttp.CertificatePinner", "check", (function(t, r) {
      if (e.d("SSL bypassing " + this), "boolean" == this.returnType.type) return !0;
    }));
  })), ignoreError((function() {
    return l("com.android.okhttp.CertificatePinner", "check$okhttp", (function(t, r) {
      e.d("SSL bypassing " + this);
    }));
  })), ignoreError((function() {
    return l("com.android.org.conscrypt.TrustManagerImpl", "verifyChain", (function(t, r) {
      return e.d("SSL bypassing " + this), r[0];
    }));
  }));
}

function w(t) {
  e.w("choose classloder: " + t), Java.enumerateClassLoaders({
    onMatch: function(r) {
      try {
        null != r.findClass(t) && (e.i("choose classloader: " + r), Reflect.set(Java.classFactory, "loader", r));
      } catch (t) {
        e.e(pretty2Json(t));
      }
    },
    onComplete: function() {
      e.d("enumerate classLoaders complete");
    }
  });
}

function O(t, r, n) {
  void 0 === r && (r = void 0), void 0 === n && (n = void 0), t = null != t ? t.trim().toLowerCase() : "", 
  r = null != r ? r.trim().toLowerCase() : "", n = null != n ? n : {
    stack: !0,
    args: !0
  }, e.w("trace classes, include: " + t + ", exclude: " + r + ", options: " + JSON.stringify(n)), 
  Java.enumerateLoadedClasses({
    onMatch: function(e) {
      var a = e.toString().toLowerCase();
      a.indexOf(t) >= 0 && ("" == r || a.indexOf(r) < 0) && u(e, d(n));
    },
    onComplete: function() {
      e.d("enumerate classLoaders complete");
    }
  });
}

function S(e) {
  l("android.app.ContextImpl", "createAppContext", (function(t, r) {
    var n = this(t, r);
    return e(n), n;
  }));
}

function j(e) {
  l("android.app.LoadedApk", "makeApplication", (function(t, r) {
    var n = this(t, r);
    return e(n), n;
  }));
}

function J(e) {
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
}

function P(e) {
  Object.defineProperties(e, {
    className: {
      configurable: !0,
      enumerable: !0,
      writable: !1,
      value: a(e.holder)
    },
    name: {
      configurable: !0,
      enumerable: !0,
      get: function() {
        var e = J(this.returnType.className), t = J(this.className) + "." + this.methodName, r = "";
        if (this.argumentTypes.length > 0) {
          r = J(this.argumentTypes[0].className);
          for (var n = 1; n < this.argumentTypes.length; n++) r = r + ", " + J(this.argumentTypes[n].className);
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
}

function E(t, r) {
  if (void 0 === r && (r = null), null != r) {
    var n = new Proxy(t, {
      apply: function(e, t, r) {
        var n = r[0], a = r[1];
        return e.apply(n, a);
      }
    });
    isFunction(r) || (r = d(r)), t.implementation = function() {
      return r.call(n, this, Array.prototype.slice.call(arguments));
    }, e.i("Hook method: " + t);
  } else t.implementation = null, e.i("Unhook method: " + t);
}

function L(e) {
  for (var t in exports.o.excludeHookPackages) if (0 == e.indexOf(exports.o.excludeHookPackages[t])) return !0;
  return !1;
}

function A(t) {
  try {
    var r = n(t);
    if (void 0 !== r) {
      for (var a = Java.cast(r, exports.o.throwableClass), o = [], s = 0, i = b(a); s < i.length; s++) {
        var l = i[s];
        o.push("    at ".concat(l));
      }
      return o.length > 0 ? "".concat(a, "\n").concat(o.join("\n")) : "".concat(a);
    }
  } catch (t) {
    e.d("getErrorStack error: ".concat(t));
  }
}

exports.use = x, exports.setWebviewDebuggingEnabled = C, exports.bypassSslPinning = k, 
exports.chooseClassLoader = w, exports.traceClasses = O, exports.runOnCreateContext = S, 
exports.runOnCreateApplication = j, exports.getErrorStack = A;

},{"./log":4}],4:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.exception = exports.event = exports.e = exports.w = exports.i = exports.d = exports.setLevel = exports.getLevel = exports.ERROR = exports.WARNING = exports.INFO = exports.DEBUG = void 0, 
exports.DEBUG = 1, exports.INFO = 2, exports.WARNING = 3, exports.ERROR = 4;

var e = exports.INFO, t = [], o = null;

function s() {
  return e;
}

function r(t) {
  e = t, n("Set log level: " + t);
}

function n(t, o) {
  e <= exports.DEBUG && v("log", {
    level: "debug",
    message: t
  }, o);
}

function p(t, o) {
  e <= exports.INFO && v("log", {
    level: "info",
    message: t
  }, o);
}

function l(t, o) {
  e <= exports.WARNING && v("log", {
    level: "warning",
    message: t
  }, o);
}

function x(t, o) {
  e <= exports.ERROR && v("log", {
    level: "error",
    message: t
  }, o);
}

function i(e, t) {
  v("msg", e, t);
}

function u(e, t) {
  v("error", {
    description: e,
    stack: t
  });
}

function v(e, s, r) {
  var n = {};
  n[e] = s, null == r ? (t.push(n), t.length >= 50 ? c() : null === o && (o = setTimeout(c, 50))) : (c(), 
  send({
    $events: [ n ]
  }, r));
}

function c() {
  if (null !== o && (clearTimeout(o), o = null), 0 !== t.length) {
    var e = t;
    t = [], send({
      $events: e
    });
  }
}

exports.getLevel = s, exports.setLevel = r, exports.d = n, exports.i = p, exports.w = l, 
exports.e = x, exports.event = i, exports.exception = u;

},{}],5:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
  value: !0
}), exports.bypassSslPinning = exports.convert2ObjcObject = exports.getEventImpl = exports.hookMethods = exports.hookMethod = void 0;

var t = require("./log"), e = require("./c");

function n(t, e, n) {
  void 0 === n && (n = null);
  var r = t;
  if ("string" == typeof r && (r = ObjC.classes[r]), void 0 === r) throw Error('cannot find class "' + t + '"');
  var o = e;
  if ("string" == typeof o && (o = r[o]), void 0 === o) throw Error('cannot find method "' + e + '" in class "' + r + '"');
  a(r, o), l(o, n);
}

function r(t, e, n) {
  void 0 === n && (n = null);
  var r = t;
  if ("string" == typeof r && (r = ObjC.classes[r]), void 0 === r) throw Error('cannot find class "' + t + '"');
  for (var o = r.$ownMethods.length, i = 0; i < o; i++) {
    var s = r.$ownMethods[i];
    if (s.indexOf(e) >= 0) {
      var c = r[s];
      a(r, c), l(c, n);
    }
  }
}

function o(n) {
  var r = new function() {
    for (var t in this.method = !0, this.thread = !1, this.stack = !1, this.args = !1, 
    this.extras = {}, n) t in this ? this[t] = n[t] : this.extras[t] = n[t];
  };
  return function(n, o) {
    var s = {};
    for (var a in r.extras) s[a] = r.extras[a];
    if (!1 !== r.method && (s.class_name = new ObjC.Object(n).$className, s.method_name = this.name, 
    s.method_simple_name = this.methodName), !1 !== r.thread && (s.thread_id = Process.getCurrentThreadId(), 
    s.thread_name = ObjC.classes.NSThread.currentThread().name().toString()), !1 !== r.args) {
      for (var l = [], c = 0; c < o.length; c++) l.push(i(o[c]));
      s.args = pretty2Json(l), s.result = null, s.error = null;
    }
    try {
      var u = this(n, o);
      return !1 !== r.args && (s.result = pretty2Json(i(u))), u;
    } catch (t) {
      throw !1 !== r.args && (s.error = pretty2Json(t)), t;
    } finally {
      if (!1 !== r.stack) {
        var d = [], h = "fuzzy" !== r.stack ? Backtracer.ACCURATE : Backtracer.FUZZY, f = Thread.backtrace(this.context, h);
        for (c = 0; c < f.length; c++) d.push(e.getDebugSymbolFromAddress(f[c]).toString());
        s.stack = d;
      }
      t.event(s);
    }
  };
}

function i(t) {
  return t instanceof NativePointer || "object" == typeof t && t.hasOwnProperty("handle") ? new ObjC.Object(t) : t;
}

function s() {
  t.w("iOS Bypass ssl pinning");
  try {
    Module.ensureInitialized("libboringssl.dylib");
  } catch (e) {
    t.d("libboringssl.dylib module not loaded. Trying to manually load it."), Module.load("libboringssl.dylib");
  }
  var n = new NativeCallback((function(e, n) {
    return t.d("custom SSL context verify callback, returning SSL_VERIFY_NONE"), 0;
  }), "int", [ "pointer", "pointer" ]);
  try {
    e.hookFunction("libboringssl.dylib", "SSL_set_custom_verify", "void", [ "pointer", "int", "pointer" ], (function(e) {
      return t.d("SSL_set_custom_verify(), setting custom callback."), e[2] = n, this(e);
    }));
  } catch (r) {
    e.hookFunction("libboringssl.dylib", "SSL_CTX_set_custom_verify", "void", [ "pointer", "int", "pointer" ], (function(e) {
      return t.d("SSL_CTX_set_custom_verify(), setting custom callback."), e[2] = n, this(e);
    }));
  }
  e.hookFunction("libboringssl.dylib", "SSL_get_psk_identity", "pointer", [ "pointer" ], (function(e) {
    return t.d('SSL_get_psk_identity(), returning "fakePSKidentity"'), Memory.allocUtf8String("fakePSKidentity");
  }));
}

function a(t, e) {
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
}

function l(e, n) {
  void 0 === n && (n = null), null != n ? (isFunction(n) || (n = o(n)), e.implementation = ObjC.implement(e, (function() {
    var t = this, r = Array.prototype.slice.call(arguments), o = r.shift(), i = r.shift(), s = new Proxy(e, {
      get: function(e, n, r) {
        return n in t ? t[n] : e[n];
      },
      apply: function(t, e, n) {
        var r = n[0], o = n[1];
        return t.origImplementation.apply(null, [].concat(r, i, o));
      }
    });
    return n.call(s, o, r);
  })), t.i("Hook method: " + e)) : (e.implementation = e.origImplementation, t.i("Unhook method: " + pretty2String(e)));
}

exports.hookMethod = n, exports.hookMethods = r, exports.getEventImpl = o, exports.convert2ObjcObject = i, 
exports.bypassSslPinning = s;

},{"./c":2,"./log":4}]},{},[1])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJpbmRleC50cyIsImxpYi9jLnRzIiwibGliL2phdmEudHMiLCJsaWIvbG9nLnRzIiwibGliL29iamMudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUE7Ozs7Ozs7O0FDQUEsSUFBQSxJQUFBLFFBQUEsY0FDQSxJQUFBLFFBQUEsWUFDQSxJQUFBLFFBQUEsZUFDQSxJQUFBLFFBQUEsZUFNTSxJQUFhLFNBQUM7RUFDaEIsT0FBTztJQUNILElBQUksVUFBVSxTQUFTLEdBQUc7TUFFdEIsS0FEQSxJQUFJLElBQVUsY0FBYyxVQUFVLEtBQzdCLElBQUksR0FBRyxJQUFJLFVBQVUsUUFBUSxLQUNsQyxLQUFXO01BQ1gsS0FBVyxjQUFjLFVBQVU7TUFFdkMsRUFBRztXQUVILEVBQUc7QUFFWDtBQUNKOztBQUVBLFFBQVEsUUFBUSxFQUFXLEVBQUksRUFBRSxLQUFLLEtBQ3RDLFFBQVEsT0FBTyxFQUFXLEVBQUksRUFBRSxLQUFLLEtBQ3JDLFFBQVEsT0FBTyxFQUFXLEVBQUksRUFBRSxLQUFLO0FBQ3JDLFFBQVEsUUFBUSxFQUFXLEVBQUksRUFBRSxLQUFLLEtBQ3RDLFFBQVEsTUFBTSxFQUFXLEVBQUksRUFBRSxLQUFLLEtBR1MsUUFBekMsT0FBTyxrQ0FDUCxPQUFPLGdDQUErQixTQUFBO0VBQ2xDLElBQUksU0FBUTtFQUNaLElBQUksYUFBaUIsT0FBTztJQUN4QixJQUFNLElBQWEsRUFBTTtTQUNOLE1BQWYsTUFDQSxJQUFROztFQUdoQixJQUFJLEtBQUssV0FBVztJQUNoQixJQUFNLElBQVksRUFBSyxjQUFjO1NBQ25CLE1BQWQsV0FDYyxNQUFWLElBQ0EsS0FBUyxvQkFBQSxPQUFvQixLQUU3QixJQUFROztFQUlwQixFQUFJLFVBQVUsS0FBSyxHQUFPO0FBQzlCOztBQWlCSixJQUFBLElBQUE7RUFBQSxTQUFBLEtBb0JBO0VBQUEsT0FsQkksRUFBQSxVQUFBLE9BQUEsU0FBSyxH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QTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FDekhBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7Ozs7OztBQzNlYSxRQUFBLFFBQVEsR0FDUixRQUFB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
