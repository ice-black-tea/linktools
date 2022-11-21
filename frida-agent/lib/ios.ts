export class IOSHelper {

    // copy from https://github.com/sensepost/objection/blob/master/agent/src/ios/pinning.ts
    bypassSslPinning() {

        Log.w("iOS Bypass ssl pinning");

        try {
            Module.ensureInitialized("libboringssl.dylib");
        } catch(err) {
            Log.d("libboringssl.dylib module not loaded. Trying to manually load it.")
            Module.load("libboringssl.dylib");  
        }

        const customVerifyCallback = new NativeCallback(function (ssl, out_alert) {
            Log.d(`custom SSL context verify callback, returning SSL_VERIFY_NONE`);
            return 0;
        }, "int", ["pointer", "pointer"]);

        try {
            CHelper.hookFunction("libboringssl.dylib", "SSL_set_custom_verify", "void", ["pointer", "int", "pointer"], function(args) {
                Log.d(`SSL_set_custom_verify(), setting custom callback.`);
                args[2] = customVerifyCallback;
                return this(args);
            });
        } catch (e) {
            CHelper.hookFunction("libboringssl.dylib", "SSL_CTX_set_custom_verify", "void", ["pointer", "int", "pointer"], function(args) {
                Log.d(`SSL_CTX_set_custom_verify(), setting custom callback.`);
                args[2] = customVerifyCallback;
                return this(args);
            });
        }

        CHelper.hookFunction("libboringssl.dylib", "SSL_get_psk_identity", "pointer", ["pointer"], function(args) {
            Log.d(`SSL_get_psk_identity(), returning "fakePSKidentity"`);
            return Memory.allocUtf8String("fakePSKidentity");
        });
    }

}