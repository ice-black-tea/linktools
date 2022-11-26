(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var Event = (function () {
    function Event(type, message, data) {
        this.type = null;
        this.message = null;
        this.data = null;
        this.type = type;
        this.message = message;
        this.data = data;
    }
    return Event;
}());
var Emitter = (function () {
    function Emitter() {
        var _this = this;
        this.pendingEvents = [];
        this.flushTimer = null;
        this.flush = function () {
            if (_this.flushTimer !== null) {
                clearTimeout(_this.flushTimer);
                _this.flushTimer = null;
            }
            if (_this.pendingEvents.length === 0) {
                return;
            }
            var events = _this.pendingEvents;
            _this.pendingEvents = [];
            var messages = [];
            while (events.length > 0) {
                var event_1 = events.shift();
                if (event_1.data != null) {
                    if (messages.length > 0) {
                        send({ $events: messages });
                        messages = [];
                    }
                    send({ $event: event_1 }, event_1.data);
                }
                else {
                    var message = {};
                    message[event_1.type] = event_1.message;
                    messages.push(message);
                }
            }
            if (messages.length > 0) {
                send({ $events: messages });
                messages = null;
            }
        };
    }
    Emitter.prototype.emit = function (type, message, data) {
        this.pendingEvents.push(new Event(type, message, data));
        if (this.flushTimer === null) {
            this.flushTimer = setTimeout(this.flush, 50);
        }
    };
    return Emitter;
}());
var EmitterWrapper = (function () {
    function EmitterWrapper() {
    }
    EmitterWrapper.prototype.emit = function (message, data) {
        $emitter.emit("msg", message, data);
    };
    return EmitterWrapper;
}());
var Log = (function () {
    function Log() {
        this.DEBUG = 1;
        this.INFO = 2;
        this.WARNING = 3;
        this.ERROR = 4;
        this.$level = this.INFO;
    }
    Object.defineProperty(Log.prototype, "level", {
        get: function () {
            return this.$level;
        },
        enumerable: false,
        configurable: true
    });
    Log.prototype.setLevel = function (level) {
        this.$level = level;
        this.d("Set log level: " + level);
    };
    Log.prototype.d = function (message, data) {
        if (this.$level <= this.DEBUG) {
            $emitter.emit("log", { level: "debug", message: message }, data);
        }
    };
    Log.prototype.i = function (message, data) {
        if (this.$level <= this.INFO) {
            $emitter.emit("log", { level: "info", message: message }, data);
        }
    };
    Log.prototype.w = function (message, data) {
        if (this.$level <= this.WARNING) {
            $emitter.emit("log", { level: "warning", message: message }, data);
        }
    };
    Log.prototype.e = function (message, data) {
        if (this.$level <= this.ERROR) {
            $emitter.emit("log", { level: "error", message: message }, data);
        }
    };
    return Log;
}());
var ScriptLoader = (function () {
    function ScriptLoader() {
    }
    ScriptLoader.prototype.load = function (scripts, parameters) {
        Object.defineProperties(globalThis, {
            parameters: {
                configurable: true,
                enumerable: true,
                value: parameters
            }
        });
        for (var _i = 0, scripts_1 = scripts; _i < scripts_1.length; _i++) {
            var script = scripts_1[_i];
            try {
                (1, eval)(script.source);
            }
            catch (e) {
                var message = e.hasOwnProperty("stack") ? e.stack : e;
                throw new Error("Unable to load ".concat(script.filename, ": ").concat(message));
            }
        }
    };
    return ScriptLoader;
}());
var loader = new ScriptLoader();
rpc.exports = {
    loadScripts: loader.load.bind(loader),
};
var c_1 = require("./lib/c");
var java_1 = require("./lib/java");
var android_1 = require("./lib/android");
var objc_1 = require("./lib/objc");
var ios_1 = require("./lib/ios");
var $emitter = new Emitter();
var emitter = new EmitterWrapper();
var log = new Log();
var cHelper = new c_1.CHelper();
var javaHelper = new java_1.JavaHelper();
var androidHelper = new android_1.AndroidHelper();
var objCHelper = new objc_1.ObjCHelper();
var iosHelper = new ios_1.IOSHelper();
Object.defineProperties(globalThis, {
    Emitter: {
        enumerable: true,
        value: emitter
    },
    Log: {
        enumerable: true,
        value: log
    },
    CHelper: {
        enumerable: true,
        value: cHelper
    },
    JavaHelper: {
        enumerable: true,
        value: javaHelper
    },
    AndroidHelper: {
        enumerable: true,
        value: androidHelper
    },
    ObjCHelper: {
        enumerable: true,
        value: objCHelper
    },
    IOSHelper: {
        enumerable: true,
        value: iosHelper
    },
    ignoreError: {
        enumerable: false,
        value: function (fn, defautValue) {
            if (defautValue === void 0) { defautValue = undefined; }
            try {
                return fn();
            }
            catch (e) {
                log.d("Catch ignored error. " + e);
                return defautValue;
            }
        }
    },
    parseBoolean: {
        enumerable: false,
        value: function (value, defaultValue) {
            if (defaultValue === void 0) { defaultValue = undefined; }
            if (typeof (value) === "boolean") {
                return value;
            }
            if (typeof (value) === "string") {
                var lower = value.toLowerCase();
                if (lower === "true") {
                    return true;
                }
                else if (lower === "false") {
                    return false;
                }
            }
            return defaultValue;
        }
    },
    pretty2String: {
        enumerable: false,
        value: function (obj) {
            obj = pretty2Json(obj);
            return obj instanceof Object ? JSON.stringify(obj) : obj;
        }
    },
    pretty2Json: {
        enumerable: false,
        value: function (obj) {
            if (!(obj instanceof Object)) {
                return obj;
            }
            if (Array.isArray(obj) || javaHelper.isArray(obj)) {
                var result = [];
                for (var i = 0; i < obj.length; i++) {
                    result.push(pretty2Json(obj[i]));
                }
                return result;
            }
            return ignoreError(function () { return obj.toString(); });
        }
    }
});

},{"./lib/android":2,"./lib/c":3,"./lib/ios":4,"./lib/java":5,"./lib/objc":6}],2:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AndroidHelper = void 0;
var AndroidHelper = (function () {
    function AndroidHelper() {
    }
    AndroidHelper.prototype.setWebviewDebuggingEnabled = function () {
        Log.w("Android Enable Webview Debugging");
        Java.perform(function () {
            var WebView = "android.webkit.WebView";
            JavaHelper.hookMethods(WebView, "setWebContentsDebuggingEnabled", function (obj, args) {
                Log.d("android.webkit.WebView.setWebContentsDebuggingEnabled: " + args[0]);
                args[0] = true;
                return this(obj, args);
            });
            JavaHelper.hookMethods(WebView, "loadUrl", function (obj, args) {
                Log.d("android.webkit.WebView.loadUrl: " + args[0]);
                obj.setWebContentsDebuggingEnabled(true);
                return this(obj, args);
            });
            var UCWebView = "com.uc.webview.export.WebView";
            ignoreError(function () {
                return JavaHelper.hookMethods(WebView, "setWebContentsDebuggingEnabled", function (obj, args) {
                    Log.d("com.uc.webview.export.WebView.setWebContentsDebuggingEnabled: " + args[0]);
                    args[0] = true;
                    return this(obj, args);
                });
            });
            ignoreError(function () {
                return JavaHelper.hookMethods(UCWebView, "loadUrl", function (obj, args) {
                    Log.d("com.uc.webview.export.WebView.loadUrl: " + args[0]);
                    obj.setWebContentsDebuggingEnabled(true);
                    return this(obj, args);
                });
            });
        });
    };
    AndroidHelper.prototype.bypassSslPinning = function () {
        Log.w("Android Bypass ssl pinning");
        Java.perform(function () {
            var arraysClass = Java.use("java.util.Arrays");
            ignoreError(function () {
                return JavaHelper.hookMethods("com.android.org.conscrypt.TrustManagerImpl", "checkServerTrusted", function (obj, args) {
                    Log.d('Bypassing TrustManagerImpl checkServerTrusted');
                    if (this.returnType.type == 'void') {
                        return;
                    }
                    else if (this.returnType.type == "pointer" && this.returnType.className == "java.util.List") {
                        return arraysClass.asList(args[0]);
                    }
                });
            });
            ignoreError(function () {
                return JavaHelper.hookMethods("com.google.android.gms.org.conscrypt.Platform", "checkServerTrusted", function (obj, args) {
                    Log.d('Bypassing Platform checkServerTrusted {1}');
                });
            });
            ignoreError(function () {
                return JavaHelper.hookMethods("com.android.org.conscrypt.Platform", "checkServerTrusted", function (obj, args) {
                    Log.d('Bypassing Platform checkServerTrusted {2}');
                });
            });
        });
    };
    AndroidHelper.prototype.chooseClassLoader = function (className) {
        Log.w("choose classloder: " + className);
        Java.perform(function () {
            Java.enumerateClassLoaders({
                onMatch: function (loader) {
                    try {
                        var clazz = loader.findClass(className);
                        if (clazz != null) {
                            Log.i("choose classloader: " + loader);
                            Reflect.set(Java.classFactory, "loader", loader);
                        }
                    }
                    catch (e) {
                        Log.e(pretty2Json(e));
                    }
                }, onComplete: function () {
                    Log.d("enumerate classLoaders complete");
                }
            });
        });
    };
    AndroidHelper.prototype.traceClasses = function (include, exclude, options) {
        if (exclude === void 0) { exclude = void 0; }
        if (options === void 0) { options = void 0; }
        include = include != null ? include.trim().toLowerCase() : "";
        exclude = exclude != null ? exclude.trim().toLowerCase() : "";
        options = options != null ? options : { stack: true, args: true };
        Log.w("choose classes, include: " + include + ", exclude: " + exclude + ", options: " + JSON.stringify(options));
        Java.perform(function () {
            Java.enumerateLoadedClasses({
                onMatch: function (className) {
                    var targetClassName = className.toString().toLowerCase();
                    if (targetClassName.indexOf(include) >= 0) {
                        if (exclude == "" || targetClassName.indexOf(exclude) < 0) {
                            JavaHelper.hookAllMethods(className, JavaHelper.getEventImpl(options));
                        }
                    }
                }, onComplete: function () {
                    Log.d("enumerate classLoaders complete");
                }
            });
        });
    };
    return AndroidHelper;
}());
exports.AndroidHelper = AndroidHelper;

},{}],3:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CHelper = void 0;
var CHelper = (function () {
    function CHelper() {
        this.$funcCaches = {};
    }
    Object.defineProperty(CHelper.prototype, "dlopen", {
        get: function () {
            return this.getExportFunction(null, "dlopen", "pointer", ["pointer", "int"]);
        },
        enumerable: false,
        configurable: true
    });
    CHelper.prototype.getExportFunction = function (moduleName, exportName, retType, argTypes) {
        var key = (moduleName || "") + "|" + exportName;
        if (key in this.$funcCaches) {
            return this.$funcCaches[key];
        }
        var ptr = Module.findExportByName(moduleName, exportName);
        if (ptr === null) {
            throw Error("cannot find " + exportName);
        }
        this.$funcCaches[key] = new NativeFunction(ptr, retType, argTypes);
        return this.$funcCaches[key];
    };
    CHelper.prototype.hookFunctionWithCallbacks = function (moduleName, exportName, callbacks) {
        var funcPtr = Module.findExportByName(moduleName, exportName);
        if (funcPtr === null) {
            throw Error("cannot find " + exportName);
        }
        var proxyHandler = {
            get: function (target, p, receiver) {
                switch (p) {
                    case "name": return exportName;
                    default: return target[p];
                }
                ;
            },
        };
        var cb = {};
        if ("onEnter" in callbacks) {
            cb["onEnter"] = function (args) {
                var fn = callbacks.onEnter;
                fn.call(new Proxy(this, proxyHandler), args);
            };
        }
        if ("onLeave" in callbacks) {
            cb["onLeave"] = function (ret) {
                var fn = callbacks.onLeave;
                fn.call(new Proxy(this, proxyHandler), ret);
            };
        }
        var result = Interceptor.attach(funcPtr, cb);
        Log.i("Hook function: " + exportName + " (" + funcPtr + ")");
        return result;
    };
    CHelper.prototype.hookFunction = function (moduleName, exportName, retType, argTypes, impl) {
        var func = this.getExportFunction(moduleName, exportName, retType, argTypes);
        if (func === null) {
            throw Error("cannot find " + exportName);
        }
        var callbackArgTypes = argTypes;
        Interceptor.replace(func, new NativeCallback(function () {
            var self = this;
            var targetArgs = [];
            for (var i = 0; i < argTypes.length; i++) {
                targetArgs[i] = arguments[i];
            }
            var proxy = new Proxy(func, {
                get: function (target, p, receiver) {
                    switch (p) {
                        case "name": return exportName;
                        case "argumentTypes": return argTypes;
                        case "returnType": return retType;
                        case "context": return self.context;
                        default: target[p];
                    }
                    ;
                },
                apply: function (target, thisArg, argArray) {
                    var f = target;
                    return f.apply(null, argArray[0]);
                }
            });
            return impl.call(proxy, targetArgs);
        }, retType, callbackArgTypes));
        Log.i("Hook function: " + exportName + " (" + func + ")");
    };
    CHelper.prototype.getEventImpl = function (options) {
        var opts = new function () {
            this.method = true;
            this.thread = false;
            this.stack = false;
            this.args = false;
            this.extras = {};
            for (var key in options) {
                if (key in this) {
                    this[key] = options[key];
                }
                else {
                    this.extras[key] = options[key];
                }
            }
        };
        var result = function (args) {
            var event = {};
            for (var key in opts.extras) {
                event[key] = opts.extras[key];
            }
            if (opts.method) {
                event["method_name"] = this.name;
            }
            if (opts.thread) {
                event["thread_id"] = Process.getCurrentThreadId();
            }
            if (opts.args) {
                event["args"] = pretty2Json(args);
                event["result"] = null;
                event["error"] = null;
            }
            try {
                var result_1 = this(args);
                if (opts.args) {
                    event["result"] = pretty2Json(result_1);
                }
                return result_1;
            }
            catch (e) {
                if (opts.args) {
                    event["error"] = pretty2Json(e);
                }
                throw e;
            }
            finally {
                if (opts.stack) {
                    var stack = [];
                    var elements = Thread.backtrace(this.context, Backtracer.ACCURATE);
                    for (var i = 0; i < elements.length; i++) {
                        stack.push(DebugSymbol.fromAddress(elements[i]).toString());
                    }
                    event["stack"] = stack;
                }
                Emitter.emit(event);
            }
        };
        result["onLeave"] = function (ret) {
            var event = {};
            for (var key in opts.extras) {
                event[key] = opts.extras[key];
            }
            if (opts.method == true) {
                event["method_name"] = this.name;
            }
            if (opts.thread === true) {
                event["thread_id"] = Process.getCurrentThreadId();
            }
            if (opts.args === true) {
                event["result"] = pretty2Json(ret);
            }
            if (opts.stack === true) {
                var stack = [];
                var elements = Thread.backtrace(this.context, Backtracer.ACCURATE);
                for (var i = 0; i < elements.length; i++) {
                    stack.push(DebugSymbol.fromAddress(elements[i]).toString());
                }
                event["stack"] = stack;
            }
            Emitter.emit(event);
        };
        return result;
    };
    return CHelper;
}());
exports.CHelper = CHelper;

},{}],4:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.IOSHelper = void 0;
var IOSHelper = (function () {
    function IOSHelper() {
    }
    IOSHelper.prototype.bypassSslPinning = function () {
        Log.w("iOS Bypass ssl pinning");
        try {
            Module.ensureInitialized("libboringssl.dylib");
        }
        catch (err) {
            Log.d("libboringssl.dylib module not loaded. Trying to manually load it.");
            Module.load("libboringssl.dylib");
        }
        var customVerifyCallback = new NativeCallback(function (ssl, out_alert) {
            Log.d("custom SSL context verify callback, returning SSL_VERIFY_NONE");
            return 0;
        }, "int", ["pointer", "pointer"]);
        try {
            CHelper.hookFunction("libboringssl.dylib", "SSL_set_custom_verify", "void", ["pointer", "int", "pointer"], function (args) {
                Log.d("SSL_set_custom_verify(), setting custom callback.");
                args[2] = customVerifyCallback;
                return this(args);
            });
        }
        catch (e) {
            CHelper.hookFunction("libboringssl.dylib", "SSL_CTX_set_custom_verify", "void", ["pointer", "int", "pointer"], function (args) {
                Log.d("SSL_CTX_set_custom_verify(), setting custom callback.");
                args[2] = customVerifyCallback;
                return this(args);
            });
        }
        CHelper.hookFunction("libboringssl.dylib", "SSL_get_psk_identity", "pointer", ["pointer"], function (args) {
            Log.d("SSL_get_psk_identity(), returning \"fakePSKidentity\"");
            return Memory.allocUtf8String("fakePSKidentity");
        });
    };
    return IOSHelper;
}());
exports.IOSHelper = IOSHelper;

},{}],5:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.JavaHelper = void 0;
var JavaHelper = (function () {
    function JavaHelper() {
    }
    Object.defineProperty(JavaHelper.prototype, "classClass", {
        get: function () {
            return Java.use("java.lang.Class");
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(JavaHelper.prototype, "stringClass", {
        get: function () {
            return Java.use("java.lang.String");
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(JavaHelper.prototype, "threadClass", {
        get: function () {
            return Java.use("java.lang.Thread");
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(JavaHelper.prototype, "throwableClass", {
        get: function () {
            return Java.use("java.lang.Throwable");
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(JavaHelper.prototype, "uriClass", {
        get: function () {
            return Java.use("android.net.Uri");
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(JavaHelper.prototype, "urlClass", {
        get: function () {
            return Java.use("java.net.URL");
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(JavaHelper.prototype, "mapClass", {
        get: function () {
            return Java.use("java.util.Map");
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(JavaHelper.prototype, "applicationContext", {
        get: function () {
            var activityThreadClass = Java.use('android.app.ActivityThread');
            return activityThreadClass.currentApplication().getApplicationContext();
        },
        enumerable: false,
        configurable: true
    });
    JavaHelper.prototype.isArray = function (obj) {
        if (obj.hasOwnProperty("class") && obj.class instanceof Object) {
            if (obj.class.hasOwnProperty("isArray") && obj.class.isArray()) {
                return true;
            }
        }
        return false;
    };
    JavaHelper.prototype.findClass = function (className, classloader) {
        if (classloader === void 0) { classloader = void 0; }
        if (classloader !== void 0 && classloader != null) {
            var originClassloader = Java.classFactory.loader;
            try {
                Reflect.set(Java.classFactory, "loader", classloader);
                return Java.use(className);
            }
            finally {
                Reflect.set(Java.classFactory, "loader", originClassloader);
            }
        }
        else {
            if (parseInt(Java.androidVersion) < 7) {
                return Java.use(className);
            }
            var error = null;
            var loaders = Java.enumerateClassLoadersSync();
            for (var i in loaders) {
                try {
                    var clazz = this.findClass(className, loaders[i]);
                    if (clazz != null) {
                        return clazz;
                    }
                }
                catch (e) {
                    if (error == null) {
                        error = e;
                    }
                }
            }
            throw error;
        }
    };
    JavaHelper.prototype.$getClassName = function (clazz) {
        var className = clazz.$className;
        if (className != void 0) {
            return className;
        }
        className = clazz.__name__;
        if (className != void 0) {
            return className;
        }
        if (clazz.$classWrapper != void 0) {
            className = clazz.$classWrapper.$className;
            if (className != void 0) {
                return className;
            }
            className = clazz.$classWrapper.__name__;
            if (className != void 0) {
                return className;
            }
        }
        Log.e("Cannot get class name: " + clazz);
    };
    JavaHelper.prototype.$getClassMethod = function (clazz, methodName) {
        var method = clazz[methodName];
        if (method !== void 0) {
            return method;
        }
        if (methodName[0] == "$") {
            method = clazz["_" + methodName];
            if (method !== void 0) {
                return method;
            }
        }
        return void 0;
    };
    JavaHelper.prototype.$defineMethodProperties = function (method) {
        Object.defineProperties(method, {
            className: {
                configurable: true,
                enumerable: true,
                writable: false,
                value: this.$getClassName(method.holder)
            },
            name: {
                configurable: true,
                enumerable: true,
                get: function () {
                    var ret = this.returnType.className;
                    var name = this.className + "." + this.methodName;
                    var args = "";
                    if (this.argumentTypes.length > 0) {
                        args = this.argumentTypes[0].className;
                        for (var i = 1; i < this.argumentTypes.length; i++) {
                            args = args + ", " + this.argumentTypes[i].className;
                        }
                    }
                    return ret + " " + name + "(" + args + ")";
                }
            },
            toString: {
                configurable: true,
                value: function () {
                    return this.name;
                }
            }
        });
    };
    JavaHelper.prototype.$hookMethod = function (method, impl) {
        if (impl === void 0) { impl = null; }
        if (impl != null) {
            var proxy_1 = new Proxy(method, {
                apply: function (target, thisArg, argArray) {
                    var obj = argArray[0];
                    var args = argArray[1];
                    return target.apply(obj, args);
                }
            });
            method.implementation = function () {
                return impl.call(proxy_1, this, Array.prototype.slice.call(arguments));
            };
            Log.i("Hook method: " + method);
        }
        else {
            method.implementation = null;
            Log.i("Unhook method: " + method);
        }
    };
    JavaHelper.prototype.hookMethod = function (clazz, method, signatures, impl) {
        if (impl === void 0) { impl = null; }
        var targetMethod = method;
        if (typeof (targetMethod) === "string") {
            var methodName = targetMethod;
            var targetClass = clazz;
            if (typeof (targetClass) === "string") {
                targetClass = this.findClass(targetClass);
            }
            var method_1 = this.$getClassMethod(targetClass, methodName);
            if (method_1 === void 0) {
                Log.w("Cannot find method: " + this.$getClassName(targetClass) + "." + methodName);
                return;
            }
            if (signatures != null) {
                var targetSignatures = signatures;
                for (var i in targetSignatures) {
                    if (typeof (targetSignatures[i]) !== "string") {
                        targetSignatures[i] = this.$getClassName(targetSignatures[i]);
                    }
                }
                targetMethod = method_1.overload.apply(method_1, targetSignatures);
            }
            else if (method_1.overloads.length == 1) {
                targetMethod = method_1.overloads[0];
            }
            else {
                throw Error(this.$getClassName(targetClass) + "." + methodName + " has too many overloads");
            }
        }
        this.$defineMethodProperties(targetMethod);
        this.$hookMethod(targetMethod, impl);
    };
    JavaHelper.prototype.hookMethods = function (clazz, methodName, impl) {
        if (impl === void 0) { impl = null; }
        var targetClass = clazz;
        if (typeof (targetClass) === "string") {
            targetClass = this.findClass(targetClass);
        }
        var method = this.$getClassMethod(targetClass, methodName);
        if (method === void 0) {
            Log.w("Cannot find method: " + this.$getClassName(targetClass) + "." + methodName);
            return;
        }
        for (var i = 0; i < method.overloads.length; i++) {
            var targetMethod = method.overloads[i];
            if (targetMethod.returnType !== void 0 &&
                targetMethod.returnType.className !== void 0) {
                this.$defineMethodProperties(targetMethod);
                this.$hookMethod(targetMethod, impl);
            }
        }
    };
    JavaHelper.prototype.hookAllConstructors = function (clazz, impl) {
        if (impl === void 0) { impl = null; }
        var targetClass = clazz;
        if (typeof (targetClass) === "string") {
            targetClass = this.findClass(targetClass);
        }
        this.hookMethods(targetClass, "$init", impl);
    };
    JavaHelper.prototype.$isExcludeClass = function (className) {
        return false ||
            className.indexOf("java.lang.") == 0 ||
            className.indexOf("android.os.") == 0 ||
            false;
    };
    JavaHelper.prototype.hookAllMethods = function (clazz, impl) {
        if (impl === void 0) { impl = null; }
        var targetClass = clazz;
        if (typeof (targetClass) === "string") {
            targetClass = this.findClass(targetClass);
        }
        var methodNames = [];
        var superJavaClass = null;
        var targetJavaClass = targetClass.class;
        while (targetJavaClass != null) {
            var methods = targetJavaClass.getDeclaredMethods();
            for (var i = 0; i < methods.length; i++) {
                var method = methods[i];
                var methodName = method.getName();
                if (methodNames.indexOf(methodName) < 0) {
                    methodNames.push(methodName);
                    this.hookMethods(targetClass, methodName, impl);
                }
            }
            superJavaClass = targetJavaClass.getSuperclass();
            targetJavaClass.$dispose();
            if (superJavaClass == null) {
                break;
            }
            targetJavaClass = Java.cast(superJavaClass, this.classClass);
            if (this.$isExcludeClass(targetJavaClass.getName())) {
                break;
            }
        }
    };
    JavaHelper.prototype.hookClass = function (clazz, impl) {
        if (impl === void 0) { impl = null; }
        var targetClass = clazz;
        if (typeof (targetClass) === "string") {
            targetClass = this.findClass(targetClass);
        }
        this.hookAllConstructors(targetClass, impl);
        this.hookAllMethods(targetClass, impl);
    };
    JavaHelper.prototype.getEventImpl = function (options) {
        var javaHelperThis = this;
        var opts = new function () {
            this.method = true;
            this.thread = false;
            this.stack = false;
            this.args = false;
            this.extras = {};
            for (var key in options) {
                if (key in this) {
                    this[key] = options[key];
                }
                else {
                    this.extras[key] = options[key];
                }
            }
        };
        return function (obj, args) {
            var event = {};
            for (var key in opts.extras) {
                event[key] = opts.extras[key];
            }
            if (opts.method) {
                event["class_name"] = obj.$className;
                event["method_name"] = this.name;
                event["method_simple_name"] = this.methodName;
            }
            if (opts.thread) {
                event["thread_id"] = Process.getCurrentThreadId();
                event["thread_name"] = javaHelperThis.threadClass.currentThread().getName();
            }
            if (opts.args) {
                event["args"] = pretty2Json(args);
                event["result"] = null;
                event["error"] = null;
            }
            try {
                var result = this(obj, args);
                if (opts.args) {
                    event["result"] = pretty2Json(result);
                }
                return result;
            }
            catch (e) {
                if (opts.args) {
                    event["error"] = pretty2Json(e);
                }
                throw e;
            }
            finally {
                if (opts.stack) {
                    event["stack"] = pretty2Json(javaHelperThis.getStackTrace());
                }
                Emitter.emit(event);
            }
        };
    };
    JavaHelper.prototype.fromJavaArray = function (clazz, array) {
        var targetClass = clazz;
        if (typeof (targetClass) === "string") {
            targetClass = this.findClass(targetClass);
        }
        var result = [];
        var env = Java.vm.getEnv();
        for (var i = 0; i < env.getArrayLength(array.$handle); i++) {
            result.push(Java.cast(env.getObjectArrayElement(array.$handle, i), targetClass));
        }
        return result;
    };
    JavaHelper.prototype.getEnumValue = function (clazz, name) {
        var targetClass = clazz;
        if (typeof (targetClass) === "string") {
            targetClass = this.findClass(targetClass);
        }
        var values = targetClass.class.getEnumConstants();
        if (!(values instanceof Array)) {
            values = this.fromJavaArray(targetClass, values);
        }
        for (var i = 0; i < values.length; i++) {
            if (values[i].toString() === name) {
                return values[i];
            }
        }
        throw new Error("Name of " + name + " does not match " + targetClass);
    };
    JavaHelper.prototype.getStackTrace = function () {
        var result = [];
        var elements = this.throwableClass.$new().getStackTrace();
        for (var i = 0; i < elements.length; i++) {
            result.push(elements[i]);
        }
        return result;
    };
    return JavaHelper;
}());
exports.JavaHelper = JavaHelper;

},{}],6:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ObjCHelper = void 0;
var ObjCHelper = (function () {
    function ObjCHelper() {
    }
    ObjCHelper.prototype.$fixMethod = function (clazz, method) {
        var implementation = method["origImplementation"] || method.implementation;
        var className = clazz.toString();
        var methodName = ObjC.selectorAsString(method.selector);
        var isClassMethod = ObjC.classes.NSThread.hasOwnProperty(methodName);
        Object.defineProperties(method, {
            className: {
                configurable: true,
                enumerable: true,
                get: function () {
                    return className;
                },
            },
            methodName: {
                configurable: true,
                enumerable: true,
                get: function () {
                    return methodName;
                },
            },
            name: {
                configurable: true,
                enumerable: true,
                get: function () {
                    return (isClassMethod ? "+" : "-") + "[" + className + " " + methodName + "]";
                }
            },
            origImplementation: {
                configurable: true,
                enumerable: true,
                get: function () {
                    return implementation;
                }
            },
            toString: {
                value: function () {
                    return this.name;
                }
            }
        });
    };
    ObjCHelper.prototype.$hookMethod = function (method, impl) {
        if (impl === void 0) { impl = null; }
        if (impl != null) {
            method.implementation = ObjC.implement(method, function () {
                var self = this;
                var args = Array.prototype.slice.call(arguments);
                var obj = args.shift();
                var sel = args.shift();
                var proxy = new Proxy(method, {
                    get: function (target, p, receiver) {
                        if (p in self) {
                            return self[p];
                        }
                        return target[p];
                    },
                    apply: function (target, thisArg, argArray) {
                        var obj = argArray[0];
                        var args = argArray[1];
                        return target["origImplementation"].apply(null, [].concat(obj, sel, args));
                    }
                });
                return impl.call(proxy, obj, args);
            });
            Log.i("Hook method: " + method);
        }
        else {
            method.implementation = method["origImplementation"];
            Log.i("Unhook method: " + pretty2String(method));
        }
    };
    ObjCHelper.prototype.hookMethod = function (clazz, method, impl) {
        if (impl === void 0) { impl = null; }
        var targetClass = clazz;
        if (typeof (targetClass) === "string") {
            targetClass = ObjC.classes[targetClass];
        }
        if (targetClass === void 0) {
            throw Error("cannot find class \"" + clazz + "\"");
        }
        var targetMethod = method;
        if (typeof (targetMethod) === "string") {
            targetMethod = targetClass[targetMethod];
        }
        if (targetMethod === void 0) {
            throw Error("cannot find method \"" + method + "\" in class \"" + targetClass + "\"");
        }
        this.$fixMethod(targetClass, targetMethod);
        this.$hookMethod(targetMethod, impl);
    };
    ObjCHelper.prototype.hookMethods = function (clazz, name, impl) {
        if (impl === void 0) { impl = null; }
        var targetClass = clazz;
        if (typeof (targetClass) === "string") {
            targetClass = ObjC.classes[targetClass];
        }
        if (targetClass === void 0) {
            throw Error("cannot find class \"" + clazz + "\"");
        }
        var length = targetClass.$ownMethods.length;
        for (var i = 0; i < length; i++) {
            var method = targetClass.$ownMethods[i];
            if (method.indexOf(name) >= 0) {
                var targetMethod = targetClass[method];
                this.$fixMethod(targetClass, targetMethod);
                this.$hookMethod(targetMethod, impl);
            }
        }
    };
    ObjCHelper.prototype.getEventImpl = function (options) {
        var self = this;
        var opts = new function () {
            this.method = true;
            this.thread = false;
            this.stack = false;
            this.args = false;
            this.extras = {};
            for (var key in options) {
                if (key in this) {
                    this[key] = options[key];
                }
                else {
                    this.extras[key] = options[key];
                }
            }
        };
        return function (obj, args) {
            var event = {};
            for (var key in opts.extras) {
                event[key] = opts.extras[key];
            }
            if (opts.method) {
                event["class_name"] = new ObjC.Object(obj).$className;
                event["method_name"] = this.name;
                event["method_simple_name"] = this.methodName;
            }
            if (opts.thread) {
                event["thread_id"] = Process.getCurrentThreadId();
                event["thread_name"] = ObjC.classes.NSThread.currentThread().name().toString();
            }
            if (opts.args) {
                var objectArgs = [];
                for (var i = 0; i < args.length; i++) {
                    objectArgs.push(self.convert2ObjcObject(args[i]));
                }
                event["args"] = pretty2Json(objectArgs);
                event["result"] = null;
                event["error"] = null;
            }
            try {
                var result = this(obj, args);
                if (opts.args) {
                    event["result"] = pretty2Json(self.convert2ObjcObject(result));
                }
                return result;
            }
            catch (e) {
                if (opts.args) {
                    event["error"] = pretty2Json(e);
                }
                throw e;
            }
            finally {
                if (opts.stack) {
                    var stack = [];
                    var elements = Thread.backtrace(this.context, Backtracer.ACCURATE);
                    for (var i = 0; i < elements.length; i++) {
                        stack.push(DebugSymbol.fromAddress(elements[i]).toString());
                    }
                    event["stack"] = stack;
                }
                Emitter.emit(event);
            }
        };
    };
    ObjCHelper.prototype.convert2ObjcObject = function (obj) {
        if (obj instanceof NativePointer) {
            return new ObjC.Object(obj);
        }
        else if (typeof obj === 'object' && obj.hasOwnProperty('handle')) {
            return new ObjC.Object(obj);
        }
        return obj;
    };
    return ObjCHelper;
}());
exports.ObjCHelper = ObjCHelper;

},{}]},{},[1])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJpbmRleC50cyIsImxpYi9hbmRyb2lkLnRzIiwibGliL2MudHMiLCJsaWIvaW9zLnRzIiwibGliL2phdmEudHMiLCJsaWIvb2JqYy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7O0FDS0E7SUFJSSxlQUFZLElBQVksRUFBRSxPQUFlLEVBQUUsSUFBbUM7UUFIOUUsU0FBSSxHQUFXLElBQUksQ0FBQztRQUNwQixZQUFPLEdBQVcsSUFBSSxDQUFDO1FBQ3ZCLFNBQUksR0FBa0MsSUFBSSxDQUFDO1FBRXZDLElBQUksQ0FBQyxJQUFJLEdBQUcsSUFBSSxDQUFDO1FBQ2pCLElBQUksQ0FBQyxPQUFPLEdBQUcsT0FBTyxDQUFDO1FBQ3ZCLElBQUksQ0FBQyxJQUFJLEdBQUcsSUFBSSxDQUFDO0lBQ3JCLENBQUM7SUFDTCxZQUFDO0FBQUQsQ0FUQSxBQVNDLElBQUE7QUFHRDtJQUFBO1FBQUEsaUJBaURDO1FBL0NXLGtCQUFhLEdBQVksRUFBRSxDQUFDO1FBQzVCLGVBQVUsR0FBUSxJQUFJLENBQUM7UUFVdkIsVUFBSyxHQUFHO1lBQ1osSUFBSSxLQUFJLENBQUMsVUFBVSxLQUFLLElBQUksRUFBRTtnQkFDMUIsWUFBWSxDQUFDLEtBQUksQ0FBQyxVQUFVLENBQUMsQ0FBQztnQkFDOUIsS0FBSSxDQUFDLFVBQVUsR0FBRyxJQUFJLENBQUM7YUFDMUI7WUFFRCxJQUFJLEtBQUksQ0FBQyxhQUFhLENBQUMsTUFBTSxLQUFLLENBQUMsRUFBRTtnQkFDakMsT0FBTzthQUNWO1lBRUQsSUFBTSxNQUFNLEdBQUcsS0FBSSxDQUFDLGFBQWEsQ0FBQztZQUNsQyxLQUFJLENBQUMsYUFBYSxHQUFHLEVBQUUsQ0FBQztZQUV4QixJQUFJLFFBQVEsR0FBRyxFQUFFLENBQUM7WUFDbEIsT0FBTyxNQUFNLENBQUMsTUFBTSxHQUFHLENBQUMsRUFBRTtnQkFDdEIsSUFBTSxPQUFLLEdBQUcsTUFB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
