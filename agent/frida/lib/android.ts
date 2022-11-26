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

            ignoreError(() =>
                JavaHelper.hookMethods("com.android.org.conscrypt.TrustManagerImpl", "checkServerTrusted", function (obj, args) {
                    Log.d('Bypassing TrustManagerImpl checkServerTrusted');
                    if (this.returnType.type == 'void') {
                        return;
                    } else if (this.returnType.type == "pointer" && this.returnType.className == "java.util.List") {
                        return arraysClass.asList(args[0]);
                    }
                })
            );

            ignoreError(() =>
                JavaHelper.hookMethods("com.google.android.gms.org.conscrypt.Platform", "checkServerTrusted", function (obj, args) {
                    Log.d('Bypassing Platform checkServerTrusted {1}');
                })
            );

            ignoreError(() =>
                JavaHelper.hookMethods("com.android.org.conscrypt.Platform", "checkServerTrusted", function (obj, args) {
                    Log.d('Bypassing Platform checkServerTrusted {2}');
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
}
