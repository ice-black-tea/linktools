// https://github.com/frida/frida-objc-bridge/blob/main/index.js


/**
 *  用于方便调用frida的ObjC方法
 */
export class CHelper {

    $funcCaches = {};

    get dlopen(): NativeFunction<NativePointer, [NativePointerValue, number]> {
        return this.getExportFunction(null, "dlopen", "pointer", ["pointer", "int"]);
    }

    getExportFunction<RetType extends NativeFunctionReturnType, ArgTypes extends NativeFunctionArgumentType[] | []>(
        moduleName: string | null,
        exportName: string,
        retType: RetType,
        argTypes: ArgTypes
    ): NativeFunction<GetNativeFunctionReturnValue<RetType>, ResolveVariadic<Extract<GetNativeFunctionArgumentValue<ArgTypes>, unknown[]>>> {
        const key = (moduleName || "") + "|" + exportName;
        if (key in this.$funcCaches) {
            return this.$funcCaches[key];
        }
        var ptr = Module.findExportByName(moduleName, exportName);
        if (ptr === null) {
            throw Error("cannot find " + exportName);
        }
        this.$funcCaches[key] = new NativeFunction(ptr, retType, argTypes);
        return this.$funcCaches[key];
    }

    /**
     * hook指定函数名
     * @param exportName 函数名
     * @param callbacks hook回调
     * @returns InvocationListener，可用于取消hook
     */
    hookFunctionWithCallbacks(moduleName: string | null, exportName: string, callbacks: InvocationListenerCallbacks): InvocationListener {
        const funcPtr = Module.findExportByName(moduleName, exportName);
        if (funcPtr === null) {
            throw Error("cannot find " + exportName);
        }
        const proxyHandler = {
            get: function (target, p: string | symbol, receiver: any) {
                switch (p) {
                    case "name": return exportName;
                    default: return target[p];
                };
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
        Log.i("Hook function: " + exportName + " (" + funcPtr + ")");
        return result;
    }

    /**
     * hook指定函数名
     * @param exportName 函数名
     * @param retType 返回值类型
     * @param argTypes 参数类型
     * @param impl hook实现，如调用原函数： function(args) { return this(args); }
     * @returns InvocationListener，可用于取消hook
     */
    hookFunction<RetType extends NativeFunctionReturnType, ArgTypes extends NativeFunctionArgumentType[] | []>(
        moduleName: string | null,
        exportName: string,
        retType: RetType,
        argTypes: ArgTypes,
        impl: (args: any[]) => any
    ): void {
        const func = this.getExportFunction(moduleName, exportName, retType, argTypes);
        if (func === null) {
            throw Error("cannot find " + exportName);
        }

        const callbackArgTypes: any = argTypes;
        Interceptor.replace(func, new NativeCallback(function () {
            const self: any = this;
            const targetArgs = [];
            for (let i = 0; i < argTypes.length; i++) {
                targetArgs[i] = arguments[i];
            }
            const proxy = new Proxy(func, {
                get: function (target, p: string | symbol, receiver: any) {
                    switch (p) {
                        case "name": return exportName;
                        case "argumentTypes": return argTypes;
                        case "returnType": return retType;
                        case "context": return self.context;
                        default: target[p];
                    };
                },
                apply: function (target, thisArg: any, argArray: any[]) {
                    const f: any = target;
                    return f.apply(null, argArray[0]);
                }
            });
            return impl.call(proxy, targetArgs);
        }, retType, callbackArgTypes));

        Log.i("Hook function: " + exportName + " (" + func + ")");
    }

    /**
     * 获取hook实现，调用原方法并发送调用事件
     * @param options hook选项，如：{stack: true, args: true, thread: true}
     * @returns hook实现
     */
    getEventImpl(options: any): InvocationListenerCallbacks & ((args: any[]) => any) {
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
            const event = {};
            for (const key in opts.extras) {
                event[key] = opts.extras[key];
            }
            if (opts.method !== false) {
                event["method_name"] = this.name;
            }
            if (opts.thread !== false) {
                event["thread_id"] = Process.getCurrentThreadId();
            }
            if (opts.args !== false) {
                event["args"] = pretty2Json(args);
                event["result"] = null;
                event["error"] = null;
            }
            try {
                const result = this(args);
                if (opts.args !== false) {
                    event["result"] = pretty2Json(result);
                }
                return result;
            } catch (e) {
                if (opts.args !== false) {
                    event["error"] = pretty2Json(e);
                }
                throw e;
            } finally {
                if (opts.stack !== false) {
                    const stack = [];
                    const backtracer = opts.stack !== "fuzzy" ? Backtracer.ACCURATE : Backtracer.FUZZY;
                    const elements = Thread.backtrace(this.context, backtracer);
                    for (let i = 0; i < elements.length; i++) {
                        stack.push(getDebugSymbolFromAddress(elements[i]).toString());
                    }
                    event["stack"] = stack;
                }
                Emitter.emit(event);
            }
        };

        result["onLeave"] = function (ret) {
            const event = {};
            for (const key in opts.extras) {
                event[key] = opts.extras[key];
            }
            if (opts.method !== false) {
                event["method_name"] = this.name;
            }
            if (opts.thread !== false) {
                event["thread_id"] = Process.getCurrentThreadId();
            }
            if (opts.args !== false) {
                event["result"] = pretty2Json(ret);
            }
            if (opts.stack !== false) {
                const stack = [];
                const backtracer = opts.stack !== "fuzzy" ? Backtracer.ACCURATE : Backtracer.FUZZY;
                const elements = Thread.backtrace(this.context, backtracer);
                for (let i = 0; i < elements.length; i++) {
                    stack.push(getDebugSymbolFromAddress(elements[i]).toString());
                }
                event["stack"] = stack;
            }
            Emitter.emit(event);
        }

        return result;
    }

}