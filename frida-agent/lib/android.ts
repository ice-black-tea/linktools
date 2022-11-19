export class AndroidHelper {

    setWebviewDebuggingEnabled() {

        Log.i(
            '======================================================\r\n' +
            'Android Enable Webview Debugging                      \r\n' +
            '======================================================'
        );

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

        Log.i(
            '======================================================\r\n' +
            'Android Bypass ssl pinning                           \r\n' +
            '======================================================'
        );

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
}
