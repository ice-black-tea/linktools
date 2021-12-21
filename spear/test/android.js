Java.perform(function () {

    // AndroidHelper.bypassSslPinning();
    AndroidHelper.bypassSslPinningLite();
    AndroidHelper.setWebviewDebuggingEnabled();

    // send message test
    send({
        send_test: "send_test_message",
        send_test2: { log_level: Log.$level }
    });

    // spdy test
    try {
        JavaHelper.hookMethods(
            "anet.channel.entity.ConnType",
            "isHttpType",
            function (obj, args) {
                 return true;
            });
    } catch {

    }

});
