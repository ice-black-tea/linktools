import { Base, Log } from "./base";
import { JavaHelper } from "./java"

export class AndroidHelper extends Base {

    constructor() {
        super();
    }


    setWebviewDebuggingEnabled() {
        const JavaHelper: JavaHelper = globalThis.JavaHelper;

        Log.i(
            '======================================================\r\n' +
            'Android Enable Webview Debugging                      \r\n' +
            '======================================================'
        );

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
        } catch (err) {
            Log.d('Hook com.uc.webview.export.WebView.loadUrl error: ' + err, '[-]');
        }
    }


    bypassSslPinningLite() {

        const JavaHelper: JavaHelper = globalThis.JavaHelper;

        Log.i(
            '======================================================\r\n' +
            'Android Bypass ssl pinning                           \r\n' +
            '======================================================'
        );

        Java.perform(function () {
            try {
                const arraysClass = Java.use("java.util.Arrays");
                JavaHelper.hookMethods("com.android.org.conscrypt.TrustManagerImpl", "checkServerTrusted", function (obj, args) {
                    Log.d('Bypassing TrustManagerImpl checkServerTrusted');
                    if (this.returnType.type == 'void') {
                        return;
                    } else if (this.returnType.type == "pointer" && this.returnType.className == "java.util.List") {
                        return arraysClass.asList(args[0]);
                    }
                });
            } catch (err) {
                Log.d('Hook com.android.org.conscrypt.TrustManagerImpl.checkTrusted error: ' + err, '[-]');
            }

            try {
                JavaHelper.hookMethods("com.google.android.gms.org.conscrypt.Platform", "checkServerTrusted", function (obj, args) {
                    Log.d('Bypassing Platform checkServerTrusted {1}');
                });
            } catch (err) {
                Log.d('Hook com.google.android.gms.org.conscrypt.Platform.checkServerTrusted error: ' + err, '[-]');
            }

            try {
                JavaHelper.hookMethods("com.android.org.conscrypt.Platform", "checkServerTrusted", function (obj, args) {
                    Log.d('Bypassing Platform checkServerTrusted {2}');
                });
            } catch (err) {
                Log.d('Hook com.android.org.conscrypt.Platform.checkServerTrusted error: ' + err, '[-]');
            }

        });

    }


    /************************************************************************
     * Name: SSL Pinning Universal Bypass (without CA)
     * OS: Android
     * Authors: Maurizio Siddu
     * Source: https://github.com/akabe1/my-FRIDA-scripts
     *************************************************************************/
    bypassSslPinning() {

        const JavaHelper: JavaHelper = globalThis.JavaHelper;

        Log.i(
            '======================================================\r\n' +
            'Android Bypass for various Certificate Pinning methods\r\n' +
            '======================================================'
        );

        Java.perform(function () {

            // TrustManager (Android < 7) //
            ////////////////////////////////
            var TrustManager = Java.registerClass({
                // Implement a custom TrustManager
                name: 'xxx.xxx.xxx.TrustManager',
                implements: [Java.use('javax.net.ssl.X509TrustManager')],
                methods: {
                    checkClientTrusted: function (chain, authType) { },
                    checkServerTrusted: function (chain, authType) { },
                    getAcceptedIssuers: function () { return []; }
                }
            });
            // Prepare the TrustManager array to pass to SSLContext.init()
            var TrustManagers = [TrustManager.$new()];
            try {
                // Get a handle on the init() on the SSLContext class
                // Override the init method, specifying the custom TrustManager
                JavaHelper.hookMethod("javax.net.ssl.SSLContext", "init", ['[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'], function (obj, args) {
                    Log.d('Bypassing Trustmanager (Android < 7) pinner');
                    args[1] = TrustManagers;
                    return this.apply(obj, args);
                });
            } catch (err) {
                Log.d('TrustManager (Android < 7) pinner not found', '[-]');
            }

            // OkHTTPv3 (quadruple bypass) //
            /////////////////////////////////
            try {
                // Bypass OkHTTPv3 {1}
                JavaHelper.hookMethods("okhttp3.CertificatePinner", "check", function (obj, args) {
                    Log.d('Bypassing OkHTTPv3 {1}: ' + args[0]);
                });
            } catch (err) {
                Log.d('OkHTTPv3 {1} pinner not found: ' + err, '[-]');
            }
            try {
                // Bypass OkHTTPv3 {4}
                //okhttp3_Activity_4['check$okhttp'].implementation = function(a, b) {
                JavaHelper.hookMethod("okhttp3.CertificatePinner", "check$okhttp", ['java.lang.String', 'kotlin.jvm.functions.Function0'], function (obj, args) {
                    Log.d('Bypassing OkHTTPv3 {4}: ' + args[0]);
                    return;
                });
            } catch (err) {
                Log.d('OkHTTPv3 {4} pinner not found: ' + err, '[-]');
            }




            // Trustkit (triple bypass) //
            //////////////////////////////
            try {
                // Bypass Trustkit {1}
                JavaHelper.hookMethods("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier", "verify", function (obj, args) {
                    Log.d('Bypassing Trustkit {1}: ' + args[0]);
                    return true;
                });
            } catch (err) {
                Log.d('Trustkit {1} pinner not found: ' + err, '[-]');
            }
            try {
                // Bypass Trustkit {3}
                JavaHelper.hookMethods("com.datatheorem.android.trustkit.pinning.PinningTrustManager", "checkServerTrusted", function (obj, args) {
                    Log.d('Bypassing Trustkit {3}');
                });
            } catch (err) {
                Log.d('Trustkit {3} pinner not found: ' + err, '[-]');
            }




            // TrustManagerImpl (Android > 7) //
            ////////////////////////////////////
            try {
                // Bypass TrustManagerImpl (Android > 7) {1}
                var arrayListClass = Java.use("java.util.ArrayList");
                JavaHelper.hookMethods("com.android.org.conscrypt.TrustManagerImpl", "checkTrustedRecursive", function (obj, args) {
                    Log.d('Bypassing TrustManagerImpl (Android > 7) checkTrustedRecursive check: ' + args[3]);
                    return arrayListClass.$new();
                });
            } catch (err) {
                Log.d('TrustManagerImpl (Android > 7) checkTrustedRecursive check not found: ' + err, '[-]');
            }
            try {
                // Bypass TrustManagerImpl (Android > 7) {2} (probably no more necessary)
                JavaHelper.hookMethods("com.android.org.conscrypt.TrustManagerImpl", "verifyChain", function (obj, args) {
                    Log.d('Bypassing TrustManagerImpl (Android > 7) verifyChain check: ' + args[2]);
                    return args[0];
                });
            } catch (err) {
                Log.d('TrustManagerImpl (Android > 7) verifyChain check not found: ' + err, '[-]');
            }





            // Appcelerator Titanium PinningTrustManager //
            ///////////////////////////////////////////////
            try {
                JavaHelper.hookMethods("appcelerator.https.PinningTrustManager", "checkServerTrusted", function () {
                    Log.d('Bypassing Appcelerator PinningTrustManager');
                    return;
                });
            } catch (err) {
                Log.d('Appcelerator PinningTrustManager pinner not found: ' + err, '[-]');
            }




            // Fabric PinningTrustManager //
            ////////////////////////////////
            try {
                JavaHelper.hookMethods("io.fabric.sdk.android.services.network.PinningTrustManager", "checkServerTrusted", function () {
                    Log.d('Bypassing Fabric PinningTrustManager');
                    return;
                });
            } catch (err) {
                Log.d('Fabric PinningTrustManager pinner not found: ' + err, '[-]');
            }




            // OpenSSLSocketImpl Conscrypt (double bypass) //
            /////////////////////////////////////////////////
            try {
                JavaHelper.hookMethods("com.android.org.conscrypt.OpenSSLSocketImpl", "verifyCertificateChain", function () {
                    Log.d('Bypassing OpenSSLSocketImpl Conscrypt {1}');
                    return;
                });
            } catch (err) {
                Log.d('OpenSSLSocketImpl Conscrypt {1} pinner not found: ' + err, '[-]');
            }




            // OpenSSLEngineSocketImpl Conscrypt //
            ///////////////////////////////////////
            try {
                JavaHelper.hookMethods("com.android.org.conscrypt.OpenSSLEngineSocketImpl", "verifyCertificateChain", function (obj, args) {
                    Log.d('Bypassing OpenSSLEngineSocketImpl Conscrypt: ' + (args.length >= 2 ? args[1] : null));
                });
            } catch (err) {
                Log.d('OpenSSLEngineSocketImpl Conscrypt pinner not found: ' + err, '[-]');
            }




            // OpenSSLSocketImpl Apache Harmony //
            //////////////////////////////////////
            try {
                JavaHelper.hookMethods("org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl", "verifyCertificateChain", function (obj, args) {
                    Log.d('Bypassing OpenSSLSocketImpl Apache Harmony');
                });
            } catch (err) {
                Log.d('OpenSSLSocketImpl Apache Harmony pinner not found: ' + err, '[-]');
            }




            // PhoneGap sslCertificateChecker //
            ////////////////////////////////////
            try {
                JavaHelper.hookMethod("nl.xservices.plugins.sslCertificateChecker", "execute", ['java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext'], function (obj, args) {
                    Log.d('Bypassing PhoneGap sslCertificateChecker: ' + args[0]);
                    return true;
                });
            } catch (err) {
                Log.d('PhoneGap sslCertificateChecker pinner not found: ' + err, '[-]');
            }




            // IBM MobileFirst pinTrustedCertificatePublicKey (double bypass) //
            ////////////////////////////////////////////////////////////////////
            try {
                // Bypass IBM MobileFirst {1}
                var wlClientClass = Java.use('com.worklight.wlclient.api.WLClient');
                JavaHelper.hookMethods(wlClientClass.getInstance(), "pinTrustedCertificatePublicKey", function (obj, args) {
                    Log.d('Bypassing IBM MobileFirst pinTrustedCertificatePublicKey {1}: ' + args[0]);
                });
            } catch (err) {
                Log.d('IBM MobileFirst pinTrustedCertificatePublicKey {1} pinner not found: ' + err, '[-]');
            }




            // IBM WorkLight (ancestor of MobileFirst) HostNameVerifierWithCertificatePinning (quadruple bypass) //
            ///////////////////////////////////////////////////////////////////////////////////////////////////////
            try {
                // Bypass IBM WorkLight {1}
                JavaHelper.hookMethods("com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning", "verify", function (obj, args) {
                    Log.d('Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {1}: ' + args[0]);
                });
            } catch (err) {
                Log.d('IBM WorkLight HostNameVerifierWithCertificatePinning {1} pinner not found: ' + err, '[-]');
            }




            // Conscrypt CertPinManager //
            //////////////////////////////
            try {
                JavaHelper.hookMethod("com.android.org.conscrypt.CertPinManager", "checkChainPinning", ['java.lang.String', 'java.util.List'], function (obj, args) {
                    Log.d('Bypassing Conscrypt CertPinManager: ' + args[0]);
                    return true;
                });
            } catch (err) {
                Log.d('Conscrypt CertPinManager pinner not found: ' + err, '[-]');
            }




            // Conscrypt CertPinManager (Legacy) //
            ///////////////////////////////////////
            try {
                JavaHelper.hookMethod("com.android.org.conscrypt.CertPinManager", "isChainValid", ['java.lang.String', 'java.util.List'], function (obj, args) {
                    Log.d('Bypassing Conscrypt CertPinManager (Legacy): ' + args[0]);
                    return true;
                });
            } catch (err) {
                Log.d('Conscrypt CertPinManager (Legacy) pinner not found: ' + err, '[-]');
            }




            // CWAC-Netsecurity (unofficial back-port pinner for Android<4.2) CertPinManager //
            ///////////////////////////////////////////////////////////////////////////////////
            try {
                JavaHelper.hookMethod("com.commonsware.cwac.netsecurity.conscrypt.CertPinManager", "isChainValid", ['java.lang.String', 'java.util.List'], function (obj, args) {
                    Log.d('Bypassing CWAC-Netsecurity CertPinManager: ' + args[0]);
                    return true;
                });
            } catch (err) {
                Log.d('CWAC-Netsecurity CertPinManager pinner not found: ' + err, '[-]');
            }




            // Worklight Androidgap WLCertificatePinningPlugin //
            /////////////////////////////////////////////////////
            try {
                JavaHelper.hookMethod("com.worklight.androidgap.plugin.WLCertificatePinningPlugin", "execute", ['java.lang.String', 'org.json.JSONArray', 'org.apache.cordova.CallbackContext'], function (obj, args) {
                    Log.d('Bypassing Worklight Androidgap WLCertificatePinningPlugin: ' + args[0]);
                    return true;
                });
            } catch (err) {
                Log.d('Worklight Androidgap WLCertificatePinningPlugin pinner not found: ' + err, '[-]');
            }




            // Netty FingerprintTrustManagerFactory //
            //////////////////////////////////////////
            try {
                //NOTE: sometimes this below implementation could be useful 
                //var netty_FingerprintTrustManagerFactory = Java.use('org.jboss.netty.handler.ssl.util.FingerprintTrustManagerFactory');
                JavaHelper.hookMethods("io.netty.handler.ssl.util.FingerprintTrustManagerFactory", "checkTrusted", function (obj, args) {
                    Log.d('Bypassing Netty FingerprintTrustManagerFactory');
                });
            } catch (err) {
                Log.d('Netty FingerprintTrustManagerFactory pinner not found: ' + err, '[-]');
            }




            // Squareup CertificatePinner [OkHTTP<v3] (double bypass) //
            ////////////////////////////////////////////////////////////
            try {
                // Bypass Squareup CertificatePinner  {1}
                JavaHelper.hookMethods("com.squareup.okhttp.CertificatePinner", "check", function (obj, args) {
                    Log.d('Bypassing Squareup CertificatePinner {1}: ' + args[0]);
                    return;
                });
            } catch (err) {
                Log.d('Squareup CertificatePinner {1} pinner not found: ' + err, '[-]');
            }




            // Squareup OkHostnameVerifier [OkHTTP v3] (double bypass) //
            /////////////////////////////////////////////////////////////
            try {
                // Bypass Squareup OkHostnameVerifier {1}
                JavaHelper.hookMethods("com.squareup.okhttp.internal.tls.OkHostnameVerifier", "verify", function (obj, args) {
                    Log.d('Bypassing Squareup OkHostnameVerifier {1}: ' + args[0]);
                    return true;
                });
            } catch (err) {
                Log.d('Squareup OkHostnameVerifier check not found: ' + err, '[-]');
            }
            try {
                // Bypass Squareup OkHostnameVerifier {1}
                JavaHelper.hookMethods("com.android.okhttp.internal.tls.OkHostnameVerifier", "verify", function (obj, args) {
                    Log.d('Bypassing android OkHostnameVerifier {2}: ' + args[0]);
                    return true;
                });
            } catch (err) {
                Log.d('android OkHostnameVerifier check not found: ' + err, '[-]');
            }
            try {
                // Bypass Squareup OkHostnameVerifier {1}
                JavaHelper.hookMethods("okhttp3.internal.tls.OkHostnameVerifier", "verify", function (obj, args) {
                    Log.d('Bypassing okhttp3 OkHostnameVerifier {3}: ' + args[0]);
                    return true;
                });
            } catch (err) {
                Log.d('okhttp3 OkHostnameVerifier check not found: ' + err, '[-]');
            }



            // Android WebViewClient (quadruple bypass) //
            //////////////////////////////////////////////
            try {
                // Bypass WebViewClient {1} (deprecated from Android 6)
                JavaHelper.hookMethods("android.webkit.WebViewClient", "onReceivedSslError", function (obj, args) {
                    Log.d('Bypassing Android WebViewClient check {1}');
                });
            } catch (err) {
                Log.d('Android WebViewClient {1} check not found: ' + err, '[-]');
            }
            try {
                // Bypass WebViewClient {3}
                JavaHelper.hookMethods("android.webkit.WebViewClient", "onReceivedError", function (obj, args) {
                    Log.d('Bypassing Android WebViewClient check {3}');
                });
            } catch (err) {
                Log.d('Android WebViewClient {3} check not found: ' + err, '[-]');
            }



            // Apache Cordova WebViewClient //
            //////////////////////////////////
            try {
                JavaHelper.hookMethod("org.apache.cordova.CordovaWebViewClient", "onReceivedSslError", ['android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError'], function (obj, args) {
                    Log.d('Bypassing Apache Cordova WebViewClient check');
                    args[3].proceed();
                });
            } catch (err) {
                Log.d('Apache Cordova WebViewClient check not found: ' + err, '[-]');
            }




            // Boye AbstractVerifier //
            ///////////////////////////
            try {
                JavaHelper.hookMethods("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier", "verify", function (obj, args) {
                    Log.d('Bypassing Boye AbstractVerifier check: ' + args[0]);
                });
            } catch (err) {
                Log.d('Boye AbstractVerifier check not found: ' + err, '[-]');
            }




            // Apache AbstractVerifier //
            /////////////////////////////
            try {
                JavaHelper.hookMethod("org.apache.http.conn.ssl.AbstractVerifier", "verify", ['java.lang.String', '[Ljava.lang.String;', '[Ljava.lang.String;', 'boolean'], function (obj, args) {
                    Log.d('Bypassing Apache AbstractVerifier check: ' + args[0]);
                });
            } catch (err) {
                Log.d('Apache AbstractVerifier check not found: ' + err, '[-]');
            }




            // Chromium Cronet //
            /////////////////////    
            try {

                JavaHelper.hookMethod("org.chromium.net.impl.CronetEngineBuilderImpl", "enablePublicKeyPinningBypassForLocalTrustAnchors", ['boolean'], function (obj, args) {
                    Log.i("[+] Disabling Public Key pinning for local trust anchors in Chromium Cronet");
                    args[0] = true;
                    return this.apply(obj, args);
                });
            } catch (err) {
                Log.d('Chromium Cronet pinner not found: ' + err, '[-]')
            }



            // Flutter Pinning packages http_certificate_pinning and ssl_pinning_plugin (double bypass) //
            //////////////////////////////////////////////////////////////////////////////////////////////
            try {
                // Bypass HttpCertificatePinning.check {1}
                JavaHelper.hookMethods("diefferson.http_certificate_pinning.HttpCertificatePinning", "checkConnexion", function (obj, args) {
                    Log.d('Bypassing Flutter HttpCertificatePinning : ' + args[0]);
                    return true;
                });
            } catch (err) {
                Log.d('Flutter HttpCertificatePinning pinner not found: ' + err, '[-]');
            }


            // Dynamic SSLPeerUnverifiedException Patcher                                //
            // An useful technique to bypass SSLPeerUnverifiedException failures raising //
            // when the Android app uses some uncommon SSL Pinning methods or an heavily //
            // code obfuscation. Inspired by an idea of: https://github.com/httptoolkit  //
            ///////////////////////////////////////////////////////////////////////////////
            try {
                JavaHelper.hookMethods("javax.net.ssl.SSLPeerUnverifiedException", "$init", function (obj, args) {

                    Log.w("Unexpected SSLPeerUnverifiedException occurred, trying to patch it dynamically...", "[!]");

                    var stackTrace = Java.use('java.lang.Thread').currentThread().getStackTrace();
                    var exceptionStackIndex = stackTrace.findIndex(stack =>
                        stack.getClassName() === "javax.net.ssl.SSLPeerUnverifiedException"
                    );
                    // Retrieve the method raising the SSLPeerUnverifiedException
                    var callingFunctionStack = stackTrace[exceptionStackIndex + 1];
                    var className = callingFunctionStack.getClassName();
                    var methodName = callingFunctionStack.getMethodName();

                    JavaHelper.hookMethods(className, methodName, function (obj, args) {
                        // This is a improvable rudimentary fix, if not works you can patch it manually
                        if (this.returnType.type == 'void') {
                            return;
                        } else if (this.returnType.type === 'boolean') {
                            return true;
                        } else {
                            return null;
                        }
                    });

                    return this.apply(obj, args);
                });
            } catch (err) {
                Log.d("SSLPeerUnverifiedException not found: " + err, '[-]');
            }
        });
    }

}
