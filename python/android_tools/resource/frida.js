var Throwable = null;
var JavaString = null;
var Charset = null;
Java.perform(function () {
    Throwable = Java.use("java.lang.Throwable");
    JavaString = Java.use("java.lang.String");
    Charset = Java.use("java.nio.charset.Charset");
});

/*
 * byte数组转字符串，如果转不了就返回null
 * :param bytes:       字符数组
 * :param charset:     字符集(可选)
 */
function BytesToString(bytes, charset) {
    if (bytes === undefined || bytes == null) {
        return null;
    }
    try {
        charset = charset || Charset.defaultCharset();
        return JavaString.$new
            .overload("[B", "java.nio.charset.Charset")
            .call(JavaString, bytes, charset).toString();
    } catch(e) {
        return null;
    }
}

/*
 * 输出当前调用堆栈
 */
function PrintStack() {
    _PrintStack(Throwable.$new().getStackTrace(), true);
};

/*
 * 调用当前函数，并输出参数返回值
 * :param object:      对象(一般直接填this)
 * :param arguments:   arguments(固定填这个)
 * :param showStack:   是否打印栈(默认为false，可不填)
 * :param showArgs:    是否打印参数(默认为false，可不填)
 */
function CallMethod(object, arguments, showStack, showArgs) {
    showStack = showStack === true;
    showArgs = showArgs === true;
    var stackElements = Throwable.$new().getStackTrace();
    _PrintStack(stackElements, showStack);
    return _CallMethod(stackElements[0], object, arguments, showArgs);
};

/*
 * 打印栈，调用当前函数，并输出参数返回值
 * :param object:      对象(一般直接填this)
 * :param arguments:   arguments(固定填这个)
 * :param showStack:   是否打印栈(默认为true，可不填)
 * :param showArgs:    是否打印参数(默认为true，可不填)
 */
function PrintStackAndCallMethod(object, arguments, showStack, showArgs) {
    showStack = showStack !== false;
    showArgs = showArgs !== false;
    return CallMethod(object, arguments, showStack, showArgs);
}

function _PrintStack(stackElements, showStack) {
    if (!showStack) {
        return;
    }
    var body = "Stack: " + stackElements[0];
    for (var i = 0; i < stackElements.length; i++) {
        body += "\n    at " + stackElements[i];
    }
    send({"helper_stack": body});
}

function _CallMethod(stackElement, object, arguments, showArgs) {
    var args = "";
    for (var i = 0; i < arguments.length; i++) {
        args += "arguments[" + i + "],";
    }
    var method = stackElement.getMethodName();
    if (method == "<init>") {
        method = "$init";
    }
    var ret = eval("object." + method + "(" + args.substring(0, args.length - 1) + ")");
    if (!showArgs) {
        return ret;
    }
    var body = "Method: " + stackElement;
    for (var i = 0; i < arguments.length; i++) {
        body += "\n    Arguments[" + i + "]: " + arguments[i];
    }
    if (ret !== undefined) {
        body += "\n    Return: " + ret;
    }
    send({"helper_method": body});
    return ret;
}