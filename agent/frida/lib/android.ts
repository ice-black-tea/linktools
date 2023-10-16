
type UseClassCallback = (clazz: Java.Wrapper<{}>) => void;
type UseClassCallBackSet = Set<UseClassCallback>;


export class AndroidHelper {

    setWebviewDebuggingEnabled() {

        Log.w("Android Enable Webview Debugging");

        Java.perform(function () {
            let WebView = "android.webkit.WebView";
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

            let UCWebView = "com.uc.webview.export.WebView";
            ignoreError(() =>
                JavaHelper.hookMethods(WebView, "setWebContentsDebuggingEnabled", function (obj, args) {
                    Log.d("com.uc.webview.export.WebView.setWebContentsDebuggingEnabled: " + args[0]);
                    args[0] = true;
                    return this(obj, args);
                })
            );
            ignoreError(() =>
                JavaHelper.hookMethods(UCWebView, "loadUrl", function (obj, args) {
                    Log.d("com.uc.webview.export.WebView.loadUrl: " + args[0]);
                    obj.setWebContentsDebuggingEnabled(true);
                    return this(obj, args);
                })
            );
        });
    }


    bypassSslPinning() {

        Log.w("Android Bypass ssl pinning");

        Java.perform(function () {
            const arraysClass = Java.use("java.util.Arrays");

            ignoreError(() => JavaHelper.hookMethods(
                "com.android.org.conscrypt.TrustManagerImpl",
                "checkServerTrusted",
                function (obj, args) {
                    Log.d('SSL bypassing ' + this);
                    if (this.returnType.type == 'void') {
                        return;
                    } else if (this.returnType.type == "pointer" && this.returnType.className == "java.util.List") {
                        return arraysClass.asList(args[0]);
                    }
                })
            );

            ignoreError(() => JavaHelper.hookMethods(
                "com.google.android.gms.org.conscrypt.Platform",
                "checkServerTrusted",
                function (obj, args) {
                    Log.d('SSL bypassing ' + this);
                })
            );

            ignoreError(() => JavaHelper.hookMethods(
                "com.android.org.conscrypt.Platform",
                "checkServerTrusted",
                function (obj, args) {
                    Log.d('SSL bypassing ' + this);
                })
            );

            ignoreError(() => JavaHelper.hookMethods(
                "okhttp3.CertificatePinner",
                "check",
                function (obj, args) {
                    Log.d('SSL bypassing ' + this);
                    if (this.returnType.type == "boolean") {
                        return true;
                    }
                })
            );

            ignoreError(() => JavaHelper.hookMethods(
                "okhttp3.CertificatePinner",
                "check$okhttp",
                function (obj, args) {
                    Log.d('SSL bypassing ' + this);
                })
            );

            ignoreError(() => JavaHelper.hookMethods(
                "com.android.okhttp.CertificatePinner",
                "check",
                function (obj, args) {
                    Log.d('SSL bypassing ' + this);
                    if (this.returnType.type == "boolean") {
                        return true;
                    }
                })
            );

            ignoreError(() => JavaHelper.hookMethods(
                "com.android.okhttp.CertificatePinner",
                "check$okhttp",
                function (obj, args) {
                    Log.d('SSL bypassing ' + this);
                    return void 0;
                })
            );

            ignoreError(() => JavaHelper.hookMethods(
                "com.android.org.conscrypt.TrustManagerImpl",
                "verifyChain",
                function (obj, args) {
                    Log.d('SSL bypassing ' + this);
                    return args[0];
                })
            );
        });
    }

    chooseClassLoader(className) {

        Log.w("choose classloder: " + className);

        Java.perform(function () {
            Java.enumerateClassLoaders({
                onMatch: function (loader) {
                    try {
                        const clazz = loader.findClass(className);
                        if (clazz != null) {
                            Log.i("choose classloader: " + loader);
                            Reflect.set(Java.classFactory, "loader", loader);
                        }
                    } catch (e) {
                        Log.e(pretty2Json(e));
                    }
                }, onComplete: function () {
                    Log.d("enumerate classLoaders complete");
                }
            });
        });
    }

    traceClasses(include: string, exclude: string = void 0, options: any = void 0) {

        include = include != null ? include.trim().toLowerCase() : "";
        exclude = exclude != null ? exclude.trim().toLowerCase() : "";
        options = options != null ? options : { stack: true, args: true };

        Log.w("trace classes, include: " + include + ", exclude: " + exclude + ", options: " + JSON.stringify(options));

        Java.perform(function () {
            Java.enumerateLoadedClasses({
                onMatch: function (className) {
                    const targetClassName: string = className.toString().toLowerCase();
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
    }

    runOnCreateContext(fn: (context: Java.Wrapper<{}>) => any) {
        Java.perform(function () {
            JavaHelper.hookMethods("android.app.ContextImpl", "createAppContext", function (obj, args) {
                const context = this(obj, args);
                fn(context);
                return context;
            });
        });
    }

    runOnCreateApplication(fn: (application: Java.Wrapper<{}>) => any) {
        Java.perform(function () {
            JavaHelper.hookMethods("android.app.LoadedApk", "makeApplication", function (obj, args) {
                const app = this(obj, args);
                fn(app);
                return app;
            });
        });
    }

    javaUse(className: string, callback: UseClassCallback) {
        const helperThis = this;
        Java.perform(function () {
            let targetClass: Java.Wrapper<{}> = null;
            try {
                targetClass = JavaHelper.findClass(className);
            } catch (e) {
                if (helperThis.$useClassCallbackMap == null) {
                    helperThis.$useClassCallbackMap = new Map<string, UseClassCallBackSet>();
                    helperThis.$registerUseClassCallback(helperThis.$useClassCallbackMap);
                }
                if (helperThis.$useClassCallbackMap.has(className)) {
                    let callbackSet = helperThis.$useClassCallbackMap.get(className);
                    if (callbackSet !== void 0) {
                        callbackSet.add(callback);
                    }
                } else {
                    let callbackSet = new Set<UseClassCallback>();
                    callbackSet.add(callback);
                    helperThis.$useClassCallbackMap.set(className, callbackSet);
                }
                return;
            }
            callback(targetClass);
        });
    }

    $useClassCallbackMap: Map<string, UseClassCallBackSet> = null;

    $registerUseClassCallback(map: Map<string, UseClassCallBackSet>) {

        const classLoaders = Java.use("java.util.HashSet").$new();

        const tryLoadClasses = function (classLoader: Java.Wrapper<{}>) {
            let it = map.entries();
            let result: IteratorResult<[string, UseClassCallBackSet]>;
            while (result = it.next(), !result.done) {
                const name = result.value[0];
                const callbacks = result.value[1];
                let clazz = null;
                try {
                    clazz = JavaHelper.findClass(name, classLoader);
                } catch (e) {
                    // ignore
                }
                if (clazz != null) {
                    map.delete(name);
                    callbacks.forEach(function (callback, _sameCallback, _set) {
                        callback(clazz);
                    });
                }
            }
        }

        JavaHelper.hookMethod(
            "java.lang.Class",
            "forName",
            ["java.lang.String", "boolean", "java.lang.ClassLoader"],
            function (obj, args) {
                const classLoader = args[2];
                if (classLoader != null && !classLoaders.contains(classLoader)) {
                    classLoaders.add(classLoader);
                    tryLoadClasses(classLoader);
                }
                return this(obj, args);
            }
        );

        JavaHelper.hookMethod(
            "java.lang.ClassLoader",
            "loadClass",
            ["java.lang.String", "boolean"],
            function (obj, args) {
                const classLoader = obj;
                if (!classLoaders.contains(classLoader)) {
                    classLoaders.add(classLoader);
                    tryLoadClasses(classLoader);
                }
                return this(obj, args);
            }
        );
    }
}
