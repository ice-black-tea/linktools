// https://github.com/frida/frida-objc-bridge/blob/main/index.js


/**
 *  用于方便调用frida的ObjC方法
 */
export class CHelper {

    $funcCaches = {};

    get dlopen() {
        return this.getExportFunction("dlopen", "pointer", ["pointer", "int"]);
    }

    getExportFunction<RetType extends NativeFunctionReturnType, ArgTypes extends NativeFunctionArgumentType[] | []>(
        name: string,
        ret: RetType,
        args: ArgTypes
    ): NativeFunction<GetNativeFunctionReturnValue<RetType>, ResolveVariadic<Extract<GetNativeFunctionArgumentValue<ArgTypes>, unknown[]>>> {
        const key = name + "|" + ret.toString() + "|" + args.toString();
        if (key in this.$funcCaches) {
            return this.$funcCaches[key];
        }
        var ptr = Module.findExportByName(null, name);
        if (ptr === null) {
            throw Error("cannot find " + name);
        }
        this.$funcCaches[key] = new NativeFunction(ptr, ret, args);
        return this.$funcCaches[key];
    }

    /**
     * hook指定函数名
     * @param name 函数名
     * @param callbacks hook回调
     * @returns InvocationListener，可用于取消hook
     */
    hookFunctionWithCallbacks(name: string, callbacks: InvocationListenerCallbacks): InvocationListener {
        const funcPtr = Module.findExportByName(null, name);
        if (funcPtr === null) {
            throw Error("cannot find " + name);
        }
        const proxyHandler = {
            get: function (target, p: string | symbol, receiver: any) {
                switch (p) {
                    case "name": return name;
                };
                return target[p];
            },
        }
        const cb = {};
        if ("onEnter" in callbacks) {
            cb["onEnter"] = function (args) {
                const fn: any = callbacks.onEnter;
                fn.call(new Proxy(this, proxyHandler), args);
            }
        }
        if ("onLeave" in callbacks) {
            cb["onLeave"] = function (ret) {
                const fn: any = callbacks.onLeave;
                fn.call(new Proxy(this, proxyHandler), ret);
            }
        }
        const result = Interceptor.attach(funcPtr, cb);
        Log.i("Hook function: " + name + " (" + funcPtr + ")");
        return result;
    }

    /**
     * hook指定函数名
     * @param name 函数名
     * @param ret 返回值类型
     * @param args 参数类型
     * @param impl hook实现，如调用原函数： function(obj, args) { return this(obj, args); }
     * @returns InvocationListener，可用于取消hook
     */
    hookFunction<RetType extends NativeFunctionReturnType, ArgTypes extends NativeFunctionArgumentType[] | []>(
        name: string,
        ret: RetType,
        args: ArgTypes,
        impl: (args: any[]) => any
    ): InvocationListener {
        const func = this.getExportFunction(name, ret, args);
        if (func === null) {
            throw Error("cannot find " + name);
        }
        const result = Interceptor.attach(func, function ($args) {
            const self: any = this;
            const targetArgs = [];
            for (let i = 0; i < args.length; i++) {
                targetArgs[i] = $args[i];
            }
            const proxy = new Proxy(func, {
                get: function (target, p: string | symbol, receiver: any) {
                    switch (p) {
                        case "name": return name;
                        case "argumentTypes": return args;
                        case "returnType": return ret;
                    };
                    if (p in self) {
                        return self[p];
                    }
                    return target[p];
                },
                apply: function (target, thisArg: any, argArray: any[]) {
                    const f: any = target;
                    return f.apply(null, argArray[0]);
                }
            });
            return impl.call(proxy, targetArgs);
        });
        Log.i("Hook function: " + name + " (" + func + ")");
        return result;
    }

    /**
     * 获取hook实现，调用原方法并发送调用事件
     * @param options hook选项，如：{stack: true, args: true, thread: true}
     * @returns hook实现
     */
    getEventImpl(options: any, probe: boolean = false): InvocationListenerCallbacks | ((args: any[]) => any) {
        const self = this;

        const opts = new function () {
            this.method = true;
            this.thread = false;
            this.stack = false;
            this.args = false;
            this.extras = {};
            for (const key in options) {
                if (key in this) {
                    this[key] = options[key];
                } else {
                    this.extras[key] = options[key];
                }
            }
        };

        const result = function (args) {
            const result = this(args);
            const event = {};
            for (const key in opts.extras) {
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
                event["result"] = pretty2Json(result);
            }
            if (opts.stack) {
                const stack = [];
                const elements = Thread.backtrace(this.context, Backtracer.ACCURATE);
                for (let i = 0; i < elements.length; i++) {
                    stack.push(DebugSymbol.fromAddress(elements[i]).toString());
                }
                event["stack"] = stack;
            }
            send({
                event: event
            });
            return result;
        };

        result["onLeave"] = function (ret) {
            const event = {};
            for (const key in opts.extras) {
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
                const stack = [];
                const elements = Thread.backtrace(this.context, Backtracer.ACCURATE);
                for (let i = 0; i < elements.length; i++) {
                    stack.push(DebugSymbol.fromAddress(elements[i]).toString());
                }
                event["stack"] = stack;
            }
            send({
                event: event
            });
        }

        return result;
    }

}