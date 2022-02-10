(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var Log = (function () {
    function Log() {
        this.debug = 1;
        this.info = 2;
        this.warning = 3;
        this.error = 4;
        this.$level = this.info;
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
    Log.prototype.d = function (data, tag) {
        if (tag === void 0) { tag = null; }
        if (this.$level <= this.debug) {
            send({ log: { level: "debug", tag: tag, message: data } });
        }
    };
    Log.prototype.i = function (data, tag) {
        if (tag === void 0) { tag = null; }
        if (this.$level <= this.info) {
            send({ log: { level: "info", tag: tag, message: data } });
        }
    };
    Log.prototype.w = function (data, tag) {
        if (tag === void 0) { tag = null; }
        if (this.$level <= this.warning) {
            send({ log: { level: "warning", tag: tag, message: data } });
        }
    };
    Log.prototype.e = function (data, tag) {
        if (tag === void 0) { tag = null; }
        if (this.$level <= this.error) {
            send({ log: { level: "error", tag: tag, message: data } });
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
                throw new Error("Unable to load ".concat(script.filename, ": ").concat(e.stack));
            }
        }
    };
    return ScriptLoader;
}());
var loader = new ScriptLoader();
rpc.exports = {
    loadScripts: loader.load.bind(loader),
};
var java_1 = require("./lib/java");
var android_1 = require("./lib/android");
var objc_1 = require("./lib/objc");
var log = new Log();
var javaHelper = new java_1.JavaHelper();
var androidHelper = new android_1.AndroidHelper();
var objCHelper = new objc_1.ObjCHelper();
Object.defineProperties(globalThis, {
    Log: {
        enumerable: true,
        value: log
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
    pretty2String: {
        enumerable: false,
        value: function (obj) {
            obj = pretty2Json(obj);
            if (!(obj instanceof Object)) {
                return obj;
            }
            return JSON.stringify(obj);
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
            return ignoreError(function () { return obj.toString(); }, void 0);
        }
    }
});

},{"./lib/android":2,"./lib/java":3,"./lib/objc":4}],2:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AndroidHelper = void 0;
var AndroidHelper = (function () {
    function AndroidHelper() {
    }
    AndroidHelper.prototype.setWebviewDebuggingEnabled = function () {
        Log.i('======================================================\r\n' +
            'Android Enable Webview Debugging                      \r\n' +
            '======================================================');
        Java.perform(function () {
            JavaHelper.hookMethods("android.webkit.WebView", "loadUrl", function (obj, args) {
                Log.d("setWebContentsDebuggingEnabled: " + obj);
                obj.setWebContentsDebuggingEnabled(true);
                return this.apply(obj, args);
            });
        });
        try {
            JavaHelper.hookMethods("com.uc.webview.export.WebView", "loadUrl", function (obj, args) {
                Log.d("setWebContentsDebuggingEnabled: " + obj);
                obj.setWebContentsDebuggingEnabled(true);
                return this.apply(obj, args);
            });
        }
        catch (err) {
            Log.d('Hook com.uc.webview.export.WebView.loadUrl error: ' + err, '[-]');
        }
    };
    AndroidHelper.prototype.bypassSslPinningLite = function () {
        Log.i('======================================================\r\n' +
            'Android Bypass ssl pinning                           \r\n' +
            '======================================================');
        Java.perform(function () {
            try {
                var arraysClass_1 = Java.use("java.util.Arrays");
                JavaHelper.hookMethods("com.android.org.conscrypt.TrustManagerImpl", "checkServerTrusted", function (obj, args) {
                    Log.d('Bypassing TrustManagerImpl checkServerTrusted');
                    if (this.returnType.type == 'void') {
                        return;
                    }
                    else if (this.returnType.type == "pointer" && this.returnType.className == "java.util.List") {
                        return arraysClass_1.asList(args[0]);
                    }
                });
            }
            catch (err) {
                Log.d('Hook com.android.org.conscrypt.TrustManagerImpl.checkTrusted error: ' + err, '[-]');
            }
            try {
                JavaHelper.hookMethods("com.google.android.gms.org.conscrypt.Platform", "checkServerTrusted", function (obj, args) {
                    Log.d('Bypassing Platform checkServerTrusted {1}');
                });
            }
            catch (err) {
                Log.d('Hook com.google.android.gms.org.conscrypt.Platform.checkServerTrusted error: ' + err, '[-]');
            }
            try {
                JavaHelper.hookMethods("com.android.org.conscrypt.Platform", "checkServerTrusted", function (obj, args) {
                    Log.d('Bypassing Platform checkServerTrusted {2}');
                });
            }
            catch (err) {
                Log.d('Hook com.android.org.conscrypt.Platform.checkServerTrusted error: ' + err, '[-]');
            }
        });
    };
    AndroidHelper.prototype.bypassSslPinning = function () {
        Log.i('======================================================\r\n' +
            'Android Bypass for various Certificate Pinning methods\r\n' +
            '======================================================');
        Java.perform(function () {
            var TrustManager = Java.registerClass({
                name: 'xxx.xxx.xxx.TrustManager',
                implements: [Java.use('javax.net.ssl.X509TrustManager')],
                methods: {
                    checkClientTrusted: function (chain, authType) { },
                    checkServerTrusted: function (chain, authType) { },
                    getAcceptedIssuers: function () { return []; }
                }
            });
            var TrustManagers = [TrustManager.$new()];
            try {
                JavaHelper.hookMethod("javax.net.ssl.SSLContext", "init", ['[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'], function (obj, args) {
                    Log.d('Bypassing Trustmanager (Android < 7) pinner');
                    args[1] = TrustManagers;
                    return this.apply(obj, args);
                });
            }
            catch (err) {
                Log.d('TrustManager (Android < 7) pinner not found', '[-]');
            }
            try {
                JavaHelper.hookMethods("okhttp3.CertificatePinner", "check", function (obj, args) {
                    Log.d('Bypassing OkHTTPv3 {1}: ' + args[0]);
                });
            }
            catch (err) {
                Log.d('OkHTTPv3 {1} pinner not found: ' + err, '[-]');
            }
            try {
                JavaHelper.hookMethod("okhttp3.CertificatePinner", "check$okhttp", ['java.lang.String', 'kotlin.jvm.functions.Function0'], function (obj, args) {
                    Log.d('Bypassing OkHTTPv3 {4}: ' + args[0]);
                    return;
                });
            }
            catch (err) {
                Log.d('OkHTTPv3 {4} pinner not found: ' + err, '[-]');
            }
            try {
                JavaHelper.hookMethods("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier", "verify", function (obj, args) {
                    Log.d('Bypassing Trustkit {1}: ' + args[0]);
                    return true;
                });
            }
            catch (err) {
                Log.d('Trustkit {1} pinner not found: ' + err, '[-]');
            }
            try {
                JavaHelper.hookMethods("com.datatheorem.android.trustkit.pinning.PinningTrustManager", "checkServerTrusted", function (obj, args) {
                    Log.d('Bypassing Trustkit {3}');
                });
            }
            catch (err) {
                Log.d('Trustkit {3} pinner not found: ' + err, '[-]');
            }
            try {
                var arrayListClass = Java.use("java.util.ArrayList");
                JavaHelper.hookMethods("com.android.org.conscrypt.TrustManagerImpl", "checkTrustedRecursive", function (obj, args) {
                    Log.d('Bypassing TrustManagerImpl (Android > 7) checkTrustedRecursive check: ' + args[3]);
                    return arrayListClass.$new();
                });
            }
            catch (err) {
                Log.d('TrustManagerImpl (Android > 7) checkTrustedRecursive check not found: ' + err, '[-]');
            }
            try {
                JavaHelper.hookMethods("com.android.org.conscrypt.TrustManagerImpl", "verifyChain", function (obj, args) {
                    Log.d('Bypassing TrustManagerImpl (Android > 7) verifyChain check: ' + args[2]);
                    return args[0];
                });
            }
            catch (err) {
                Log.d('TrustManagerImpl (Android > 7) verifyChain check not found: ' + err, '[-]');
            }
            try {
                JavaHelper.hookMethods("appcelerator.https.PinningTrustManager", "checkServerTrusted", function () {
                    Log.d('Bypassing Appcelerator PinningTrustManager');
                    return;
                });
            }
            catch (err) {
                Log.d('Appcelerator PinningTrustManager pinner not found: ' + err, '[-]');
            }
            try {
                JavaHelper.hookMethods("io.fabric.sdk.android.services.network.PinningTrustManager", "checkServerTrusted", function () {
                    Log.d('Bypassing Fabric PinningTrustManager');
                    return;
                });
            }
            catch (err) {
                Log.d('Fabric PinningTrustManager pinner not found: ' + err, '[-]');
            }
            try {
                JavaHelper.hookMethods("com.android.org.conscrypt.OpenSSLSocketImpl", "verifyCertificateChain", function () {
                    Log.d('Bypassing OpenSSLSocketImpl Conscrypt {1}');
                    return;
                });
            }
            catch (err) {
                Log.d('OpenSSLSocketImpl Conscrypt {1} pinner not found: ' + err, '[-]');
            }
            try {
                JavaHelper.hookMethods("com.android.org.conscrypt.OpenSSLEngineSocketImpl", "verifyCertificateChain", function (obj, args) {
                    Log.d('Bypassing OpenSSLEngineSocketImpl Conscrypt: ' + (args.length >= 2 ? args[1] : null));
                });
            }
            catch (err) {
                Log.d('OpenSSLEngineSocketImpl Conscrypt pinner not found: ' + err, '[-]');
            }
            try {
                JavaHelper.hookMethods("org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl", "verifyCertificateChain", function (obj, args) {
                    Log.d('Bypassing OpenSSLSocketImpl Apache Harmony');
                });
            }
            catch (err) {
                Log.d('OpenSSLSocketImpl Apache Harmony pinner not found: ' + err, '[-]');
            }
            try {
                JavaHelper.hookMethod("nl.xservices.plugins.sslCertificateChecker", "execute", ['java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext'], function (obj, args) {
                    Log.d('Bypassing PhoneGap sslCertificateChecker: ' + args[0]);
                    return true;
                });
            }
            catch (err) {
                Log.d('PhoneGap sslCertificateChecker pinner not found: ' + err, '[-]');
            }
            try {
                var wlClientClass = Java.use('com.worklight.wlclient.api.WLClient');
                JavaHelper.hookMethods(wlClientClass.getInstance(), "pinTrustedCertificatePublicKey", function (obj, args) {
                    Log.d('Bypassing IBM MobileFirst pinTrustedCertificatePublicKey {1}: ' + args[0]);
                });
            }
            catch (err) {
                Log.d('IBM MobileFirst pinTrustedCertificatePublicKey {1} pinner not found: ' + err, '[-]');
            }
            try {
                JavaHelper.hookMethods("com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning", "verify", function (obj, args) {
                    Log.d('Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {1}: ' + args[0]);
                });
            }
            catch (err) {
                Log.d('IBM WorkLight HostNameVerifierWithCertificatePinning {1} pinner not found: ' + err, '[-]');
            }
            try {
                JavaHelper.hookMethod("com.android.org.conscrypt.CertPinManager", "checkChainPinning", ['java.lang.String', 'java.util.List'], function (obj, args) {
                    Log.d('Bypassing Conscrypt CertPinManager: ' + args[0]);
                    return true;
                });
            }
            catch (err) {
                Log.d('Conscrypt CertPinManager pinner not found: ' + err, '[-]');
            }
            try {
                JavaHelper.hookMethod("com.android.org.conscrypt.CertPinManager", "isChainValid", ['java.lang.String', 'java.util.List'], function (obj, args) {
                    Log.d('Bypassing Conscrypt CertPinManager (Legacy): ' + args[0]);
                    return true;
                });
            }
            catch (err) {
                Log.d('Conscrypt CertPinManager (Legacy) pinner not found: ' + err, '[-]');
            }
            try {
                JavaHelper.hookMethod("com.commonsware.cwac.netsecurity.conscrypt.CertPinManager", "isChainValid", ['java.lang.String', 'java.util.List'], function (obj, args) {
                    Log.d('Bypassing CWAC-Netsecurity CertPinManager: ' + args[0]);
                    return true;
                });
            }
            catch (err) {
                Log.d('CWAC-Netsecurity CertPinManager pinner not found: ' + err, '[-]');
            }
            try {
                JavaHelper.hookMethod("com.worklight.androidgap.plugin.WLCertificatePinningPlugin", "execute", ['java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext'], function (obj, args) {
                    Log.d('Bypassing Worklight Androidgap WLCertificatePinningPlugin: ' + args[0]);
                    return true;
                });
            }
            catch (err) {
                Log.d('Worklight Androidgap WLCertificatePinningPlugin pinner not found: ' + err, '[-]');
            }
            try {
                JavaHelper.hookMethods("io.netty.handler.ssl.util.FingerprintTrustManagerFactory", "checkTrusted", function (obj, args) {
                    Log.d('Bypassing Netty FingerprintTrustManagerFactory');
                });
            }
            catch (err) {
                Log.d('Netty FingerprintTrustManagerFactory pinner not found: ' + err, '[-]');
            }
            try {
                JavaHelper.hookMethods("com.squareup.okhttp.CertificatePinner", "check", function (obj, args) {
                    Log.d('Bypassing Squareup CertificatePinner {1}: ' + args[0]);
                    return;
                });
            }
            catch (err) {
                Log.d('Squareup CertificatePinner {1} pinner not found: ' + err, '[-]');
            }
            try {
                JavaHelper.hookMethods("com.squareup.okhttp.internal.tls.OkHostnameVerifier", "verify", function (obj, args) {
                    Log.d('Bypassing Squareup OkHostnameVerifier {1}: ' + args[0]);
                    return true;
                });
            }
            catch (err) {
                Log.d('Squareup OkHostnameVerifier check not found: ' + err, '[-]');
            }
            try {
                JavaHelper.hookMethods("com.android.okhttp.internal.tls.OkHostnameVerifier", "verify", function (obj, args) {
                    Log.d('Bypassing android OkHostnameVerifier {2}: ' + args[0]);
                    return true;
                });
            }
            catch (err) {
                Log.d('android OkHostnameVerifier check not found: ' + err, '[-]');
            }
            try {
                JavaHelper.hookMethods("okhttp3.internal.tls.OkHostnameVerifier", "verify", function (obj, args) {
                    Log.d('Bypassing okhttp3 OkHostnameVerifier {3}: ' + args[0]);
                    return true;
                });
            }
            catch (err) {
                Log.d('okhttp3 OkHostnameVerifier check not found: ' + err, '[-]');
            }
            try {
                JavaHelper.hookMethods("android.webkit.WebViewClient", "onReceivedSslError", function (obj, args) {
                    Log.d('Bypassing Android WebViewClient check {1}');
                });
            }
            catch (err) {
                Log.d('Android WebViewClient {1} check not found: ' + err, '[-]');
            }
            try {
                JavaHelper.hookMethods("android.webkit.WebViewClient", "onReceivedError", function (obj, args) {
                    Log.d('Bypassing Android WebViewClient check {3}');
                });
            }
            catch (err) {
                Log.d('Android WebViewClient {3} check not found: ' + err, '[-]');
            }
            try {
                JavaHelper.hookMethod("org.apache.cordova.CordovaWebViewClient", "onReceivedSslError", ['android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError'], function (obj, args) {
                    Log.d('Bypassing Apache Cordova WebViewClient check');
                    args[3].proceed();
                });
            }
            catch (err) {
                Log.d('Apache Cordova WebViewClient check not found: ' + err, '[-]');
            }
            try {
                JavaHelper.hookMethods("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier", "verify", function (obj, args) {
                    Log.d('Bypassing Boye AbstractVerifier check: ' + args[0]);
                });
            }
            catch (err) {
                Log.d('Boye AbstractVerifier check not found: ' + err, '[-]');
            }
            try {
                JavaHelper.hookMethod("org.apache.http.conn.ssl.AbstractVerifier", "verify", ['java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;', 'boolean'], function (obj, args) {
                    Log.d('Bypassing Apache AbstractVerifier check: ' + args[0]);
                });
            }
            catch (err) {
                Log.d('Apache AbstractVerifier check not found: ' + err, '[-]');
            }
            try {
                JavaHelper.hookMethod("org.chromium.net.impl.CronetEngineBuilderImpl", "enablePublicKeyPinningBypassForLocalTrustAnchors", ['boolean'], function (obj, args) {
                    Log.i("[+] Disabling Public Key pinning for local trust anchors in Chromium Cronet");
                    args[0] = true;
                    return this.apply(obj, args);
                });
            }
            catch (err) {
                Log.d('Chromium Cronet pinner not found: ' + err, '[-]');
            }
            try {
                JavaHelper.hookMethods("diefferson.http_certificate_pinning.HttpCertificatePinning", "checkConnexion", function (obj, args) {
                    Log.d('Bypassing Flutter HttpCertificatePinning : ' + args[0]);
                    return true;
                });
            }
            catch (err) {
                Log.d('Flutter HttpCertificatePinning pinner not found: ' + err, '[-]');
            }
            try {
                JavaHelper.hookMethods("javax.net.ssl.SSLPeerUnverifiedException", "$init", function (obj, args) {
                    Log.w("Unexpected SSLPeerUnverifiedException occurred, trying to patch it dynamically...", "[!]");
                    var stackTrace = Java.use('java.lang.Thread').currentThread().getStackTrace();
                    var exceptionStackIndex = stackTrace.findIndex(function (stack) {
                        return stack.getClassName() === "javax.net.ssl.SSLPeerUnverifiedException";
                    });
                    var callingFunctionStack = stackTrace[exceptionStackIndex + 1];
                    var className = callingFunctionStack.getClassName();
                    var methodName = callingFunctionStack.getMethodName();
                    JavaHelper.hookMethods(className, methodName, function (obj, args) {
                        if (this.returnType.type == 'void') {
                            return;
                        }
                        else if (this.returnType.type === 'boolean') {
                            return true;
                        }
                        else {
                            return null;
                        }
                    });
                    return this.apply(obj, args);
                });
            }
            catch (err) {
                Log.d("SSLPeerUnverifiedException not found: " + err, '[-]');
            }
        });
    };
    return AndroidHelper;
}());
exports.AndroidHelper = AndroidHelper;

},{}],3:[function(require,module,exports){
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
    JavaHelper.prototype.getClassName = function (clazz) {
        return clazz.$classWrapper.__name__;
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
    JavaHelper.prototype.$fixMethod = function (method) {
        Object.defineProperties(method, {
            className: {
                configurable: true,
                enumerable: true,
                get: function () {
                    return this.holder.$className || this.holder.__name__;
                },
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
                value: function () {
                    return this.name;
                }
            }
        });
    };
    JavaHelper.prototype.$hookMethod = function (method, impl) {
        if (impl === void 0) { impl = null; }
        if (impl != null) {
            var origMethod_1 = new Proxy(method, {
                get: function (target, p, receiver) {
                    return target[p];
                },
                apply: function (target, thisArg, argArray) {
                    var obj = argArray.shift();
                    var args = argArray.shift();
                    return target.apply(obj, args);
                }
            });
            method.implementation = function () {
                return impl.call(origMethod_1, this, arguments);
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
        var tragetMethod = method;
        if (typeof (tragetMethod) === "string") {
            var targetClass = clazz;
            if (typeof (targetClass) === "string") {
                targetClass = this.findClass(targetClass);
            }
            tragetMethod = targetClass[tragetMethod];
            if (signatures != null) {
                var targetSignatures = signatures;
                for (var i in targetSignatures) {
                    if (typeof (targetSignatures[i]) !== "string") {
                        targetSignatures[i] = this.getClassName(targetSignatures[i]);
                    }
                }
                tragetMethod = tragetMethod.overload.apply(tragetMethod, targetSignatures);
            }
        }
        this.$fixMethod(tragetMethod);
        this.$hookMethod(tragetMethod, impl);
    };
    JavaHelper.prototype.hookMethods = function (clazz, methodName, impl) {
        if (impl === void 0) { impl = null; }
        var targetClass = clazz;
        if (typeof (targetClass) === "string") {
            targetClass = this.findClass(targetClass);
        }
        var methods = targetClass[methodName].overloads;
        for (var i = 0; i < methods.length; i++) {
            var targetMethod = methods[i];
            if (targetMethod.returnType !== void 0 &&
                targetMethod.returnType.className !== void 0) {
                this.$fixMethod(targetMethod);
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
    JavaHelper.prototype.hookAllMethods = function (clazz, impl) {
        if (impl === void 0) { impl = null; }
        var targetClass = clazz;
        if (typeof (targetClass) === "string") {
            targetClass = this.findClass(targetClass);
        }
        var methodNames = [];
        var targetJavaClass = targetClass.class;
        while (targetJavaClass != null && targetJavaClass.getName() !== "java.lang.Object") {
            var methods = targetJavaClass.getDeclaredMethods();
            for (var i = 0; i < methods.length; i++) {
                var method = methods[i];
                var methodName = method.getName();
                if (methodNames.indexOf(methodName) < 0) {
                    methodNames.push(methodName);
                    this.hookMethods(targetClass, methodName, impl);
                }
            }
            targetJavaClass = Java.cast(targetJavaClass.getSuperclass(), this.classClass);
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
    JavaHelper.prototype.callMethod = function (obj, args) {
        var methodName = this.getStackTrace()[0].getMethodName();
        if (methodName === "<init>") {
            methodName = "$init";
        }
        return Reflect.get(obj, methodName).apply(obj, args);
    };
    JavaHelper.prototype.getEventImpl = function (options) {
        var javaHelperThis = this;
        var methodOption = true;
        var threadOption = false;
        var stackOption = false;
        var argsOption = false;
        var extras = {};
        for (var key in options) {
            if (key == "thread") {
                methodOption = options[key];
            }
            else if (key == "thread") {
                threadOption = options[key];
            }
            else if (key == "stack") {
                stackOption = options[key];
            }
            else if (key == "args") {
                argsOption = options[key];
            }
            else {
                extras[key] = options[key];
            }
        }
        return function (obj, args) {
            var result = this(obj, args);
            var event = {};
            for (var key in extras) {
                event[key] = extras[key];
            }
            if (methodOption == true) {
                event["class_name"] = obj.$className;
                event["method_name"] = this.name;
                event["method_simple_name"] = this.methodName;
            }
            if (threadOption === true) {
                event["thread_id"] = Process.getCurrentThreadId();
                event["thread_name"] = javaHelperThis.threadClass.currentThread().getName();
            }
            if (argsOption === true) {
                event["args"] = pretty2Json(Array.prototype.slice.call(args));
                event["result"] = pretty2Json(result);
            }
            if (stackOption === true) {
                event["stack"] = pretty2Json(javaHelperThis.getStackTrace());
            }
            send({ event: event });
            return result;
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
    JavaHelper.prototype.$makeStackObject = function (elements) {
        if (elements === void 0) { elements = void 0; }
        if (elements === void 0) {
            elements = this.getStackTrace();
        }
        var body = "Stack: ";
        for (var i = 0; i < elements.length; i++) {
            body += "\n    at " + pretty2String(elements[i]);
        }
        return { "stack": body };
    };
    JavaHelper.prototype.printStack = function (message) {
        if (message === void 0) { message = void 0; }
        var elements = this.getStackTrace();
        if (message == void 0) {
            message = elements[0];
        }
        Log.i(this.$makeStackObject(elements));
    };
    JavaHelper.prototype.$makeArgsObject = function (args, ret) {
        var body = "Arguments: ";
        for (var i = 0; i < args.length; i++) {
            body += "\n    Arguments[" + i + "]: " + pretty2String(args[i]);
        }
        if (ret !== void 0) {
            body += "\n    Return: " + pretty2String(ret);
        }
        return { "arguments": body };
    };
    JavaHelper.prototype.printArguments = function (args, ret) {
        Log.i(this.$makeArgsObject(args, ret));
    };
    return JavaHelper;
}());
exports.JavaHelper = JavaHelper;

},{}],4:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ObjCHelper = void 0;
var ObjCHelper = (function () {
    function ObjCHelper() {
    }
    ObjCHelper.prototype.$fixMethod = function (clazz, method) {
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
            var origImpl_1 = method.implementation;
            method.implementation = ObjC.implement(method, function () {
                var self = this;
                var args = Array.prototype.slice.call(arguments);
                var obj = args.shift();
                var sel = args.shift();
                var origMethod = new Proxy(method, {
                    get: function (target, p, receiver) {
                        if (p == "context")
                            return self.context;
                        return target[p];
                    },
                    apply: function (target, thisArg, argArray) {
                        var obj = argArray.shift();
                        var args = argArray.shift();
                        return origImpl_1.apply(null, [].concat(obj, sel, args));
                    }
                });
                return impl.call(origMethod, obj, args);
            });
            Log.i("Hook method: " + method);
        }
        else {
            method.implementation = null;
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
    ObjCHelper.prototype.getEventImpl = function (options) {
        var objCHelperThis = this;
        var methodOption = true;
        var threadOption = false;
        var stackOption = false;
        var argsOption = false;
        var extras = {};
        for (var key in options) {
            if (key == "thread") {
                methodOption = options[key];
            }
            else if (key == "thread") {
                threadOption = options[key];
            }
            else if (key == "stack") {
                stackOption = options[key];
            }
            else if (key == "args") {
                argsOption = options[key];
            }
            else {
                extras[key] = options[key];
            }
        }
        return function (obj, args) {
            var result = this(obj, args);
            var event = {};
            for (var key in extras) {
                event[key] = extras[key];
            }
            if (methodOption == true) {
                event["class_name"] = new ObjC.Object(obj).$className;
                event["method_name"] = this.name;
                event["method_simple_name"] = this.methodName;
            }
            if (threadOption === true) {
                var thread = ObjC.classes.NSThread.currentThread();
                event["thread_name"] = thread.name().toString();
            }
            if (argsOption === true) {
                var objectArgs = [];
                for (var i = 0; i < args.length; i++) {
                    objectArgs.push(objCHelperThis.convert2ObjcObject(args[i]));
                }
                event["args"] = pretty2Json(objectArgs);
                event["result"] = pretty2Json(objCHelperThis.convert2ObjcObject(result));
            }
            if (stackOption === true) {
                var stack = [];
                var elements = Thread.backtrace(this.context, Backtracer.ACCURATE);
                for (var i = 0; i < elements.length; i++) {
                    stack.push(DebugSymbol.fromAddress(elements[i]));
                }
                event["stack"] = stack;
            }
            send({ event: event });
            return result;
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJpbmRleC50cyIsImxpYi9hbmRyb2lkLnRzIiwibGliL2phdmEudHMiLCJsaWIvb2JqYy50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7O0FDS0E7SUFBQTtRQUVJLFVBQUssR0FBRyxDQUFDLENBQUM7UUFDVixTQUFJLEdBQUcsQ0FBQyxDQUFDO1FBQ1QsWUFBTyxHQUFHLENBQUMsQ0FBQztRQUNaLFVBQUssR0FBRyxDQUFDLENBQUM7UUFDRixXQUFNLEdBQUcsSUFBSSxDQUFDLElBQUksQ0FBQztJQWtDL0IsQ0FBQztJQWhDRyxzQkFBSSxzQkFBSzthQUFUO1lBQ0ksT0FBTyxJQUFJLENBQUMsTUFBTSxDQUFDO1FBQ3ZCLENBQUM7OztPQUFBO0lBRUQsc0JBQVEsR0FBUixVQUFTLEtBQWE7UUFDbEIsSUFBSSxDQUFDLE1BQU0sR0FBRyxLQUFLLENBQUM7UUFDcEIsSUFBSSxDQUFDLENBQUMsQ0FBQyxpQkFBaUIsR0FBRyxLQUFLLENBQUMsQ0FBQztJQUN0QyxDQUFDO0lBRUQsZUFBQyxHQUFELFVBQUUsSUFBUyxFQUFFLEdBQWtCO1FBQWxCLG9CQUFBLEVBQUEsVUFBa0I7UUFDM0IsSUFBSSxJQUFJLENBQUMsTUFBTSxJQUFJLElBQUksQ0FBQyxLQUFLLEVBQUU7WUFDM0IsSUFBSSxDQUFDLEVBQUUsR0FBRyxFQUFFLEVBQUUsS0FBSyxFQUFFLE9BQU8sRUFBRSxHQUFHLEVBQUUsR0FBRyxFQUFFLE9BQU8sRUFBRSxJQUFJLEVBQUUsRUFBRSxDQUFDLENBQUM7U0FDOUQ7SUFDTCxDQUFDO0lBRUQsZUFBQyxHQUFELFVBQUUsSUFBUyxFQUFFLEdBQWtCO1FBQWxCLG9CQUFBLEVBQUEsVUFBa0I7UUFDM0IsSUFBSSxJQUFJLENBQUMsTUFBTSxJQUFJLElBQUksQ0FBQyxJQUFJLEVBQUU7WUFDMUIsSUFBSSxDQUFDLEVBQUUsR0FBRyxFQUFFLEVBQUUsS0FBSyxFQUFFLE1B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
