/**
 *  用于方便调用frida的c方法
 */

import * as Log from "./log"

type HookOpts = {
    method?: boolean;
    thread?: boolean;
    stack?: boolean;
    symbol?: boolean;
    backtracer?: "accurate" | "fuzzy";
    args?: boolean;
    extras?: {
        [name: string]: any
    };
}
type HookImpl = (args: any[]) => any;

class Objects {
    get dlopen(): NativeFunction<NativePointer, [NativePointerValue, number]> {
        return getExportFunction(null, "dlopen", "pointer", ["pointer", "int"]);
    }
}

export const o = new Objects();

const $moduleMap = new ModuleMap();
const $nativeFunctionCaches = {};
const $debugSymbolAddressCaches: { [key: string]: DebugSymbol; } = {};

/**
 * 获取导出函数
 * @param moduleName 模块名
 * @param exportName 导出名
 * @param retType 返回类型
 * @param argTypes 参数类型
 * @returns function
 */
export function getExportFunction<RetType extends NativeFunctionReturnType, ArgTypes extends NativeFunctionArgumentType[] | []>(
    moduleName: string | null,
    exportName: string,
    retType: RetType,
    argTypes: ArgTypes
): NativeFunction<GetNativeFunctionReturnValue<RetType>, ResolveVariadic<Extract<GetNativeFunctionArgumentValue<ArgTypes>, unknown[]>>> {
    const key = (moduleName || "") + "|" + exportName;
    if (key in $nativeFunctionCaches) {
        return $nativeFunctionCaches[key];
    }
    var ptr = Module.findExportByName(moduleName, exportName);
    if (ptr === null) {
        throw Error("cannot find " + exportName);
    }
    $nativeFunctionCaches[key] = new NativeFunction(ptr, retType, argTypes);
    return $nativeFunctionCaches[key];
}

/**
 * hook指定函数名
 * @param moduleName 模块名称
 * @param exportName 函数名
 * @param options hook选项，如：{stack: true, args: true, thread: true}
 * @returns InvocationListener，可用于取消hook
 */
export function hookFunctionWithOptions(moduleName: string | null, exportName: string, options: HookOpts): InvocationListener {
    return hookFunctionWithCallbacks(moduleName, exportName, getEventImpl(options));
}

/**
 * hook指定函数名
 * @param moduleName 模块名称
 * @param exportName 函数名
 * @param callbacks hook回调
 * @returns InvocationListener，可用于取消hook
 */
export function hookFunctionWithCallbacks(moduleName: string | null, exportName: string, callbacks: InvocationListenerCallbacks): InvocationListener {
    const funcPtr = Module.findExportByName(moduleName, exportName);
    if (funcPtr === null) {
        throw Error("cannot find " + exportName);
    }
    const proxyHandler = {
        get: function (target, p: string | symbol, receiver: any) {
            switch (p) {
                case "name": return exportName;
                default: return target[p];
            }
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
 * @param moduleName 模块名称
 * @param exportName 函数名
 * @param retType 返回值类型
 * @param argTypes 参数类型
 * @param impl hook实现，如调用原函数： function(args) { return this(args); }
 * @returns InvocationListener，可用于取消hook
 */
export function hookFunction<RetType extends NativeFunctionReturnType, ArgTypes extends NativeFunctionArgumentType[] | []>(
    moduleName: string | null,
    exportName: string,
    retType: RetType,
    argTypes: ArgTypes,
    impl: HookImpl | HookOpts
): void {
    const func = getExportFunction(moduleName, exportName, retType, argTypes);
    if (func === null) {
        throw Error("cannot find " + exportName);
    }

    const hookImpl = isFunction(impl) ? impl as HookImpl : getEventImpl(impl as HookOpts);
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
        return hookImpl.call(proxy, targetArgs);
    }, retType, callbackArgTypes));

    Log.i("Hook function: " + exportName + " (" + func + ")");
}

/**
 * 获取hook实现，调用原方法并发送调用事件
 * @param options hook选项，如：{stack: true, args: true, thread: true}
 * @returns hook实现
 */
export function getEventImpl(options: HookOpts): InvocationListenerCallbacks & HookImpl {
    const hookOpts: HookOpts = {};
    hookOpts.method = parseBoolean(options.method, true);
    hookOpts.thread = parseBoolean(options.thread, false);
    hookOpts.stack = parseBoolean(options.stack, false);
    hookOpts.symbol = parseBoolean(options.symbol, true);
    hookOpts.backtracer = options.backtracer || "accurate";
    hookOpts.args = parseBoolean(options.args, false);
    hookOpts.extras = {};
    if (options.extras != null) {
        for (let i in options.extras) {
            hookOpts.extras[i] = options.extras[i];
        }
    }

    const result = function (args) {
        const event = {};
        for (const key in hookOpts.extras) {
            event[key] = hookOpts.extras[key];
        }
        if (hookOpts.method !== false) {
            event["method_name"] = this.name;
        }
        if (hookOpts.thread !== false) {
            event["thread_id"] = Process.getCurrentThreadId();
        }
        if (hookOpts.args !== false) {
            event["args"] = pretty2Json(args);
            event["result"] = null;
            event["error"] = null;
        }
        try {
            const result = this(args);
            if (hookOpts.args !== false) {
                event["result"] = pretty2Json(result);
            }
            return result;
        } catch (e) {
            if (hookOpts.args !== false) {
                event["error"] = pretty2Json(e);
            }
            throw e;
        } finally {
            if (hookOpts.stack !== false) {
                const stack = event["stack"] = [];
                const backtracer = hookOpts.backtracer === "accurate" ? Backtracer.ACCURATE : Backtracer.FUZZY;
                const elements = Thread.backtrace(this.context, backtracer);
                for (let i = 0; i < elements.length; i++) {
                    stack.push(getDescFromAddress(elements[i], hookOpts.symbol !== false));
                }
            }
            Log.event(event);
        }
    };

    result["onLeave"] = function (ret) {
        const event = {};
        for (const key in hookOpts.extras) {
            event[key] = hookOpts.extras[key];
        }
        if (hookOpts.method !== false) {
            event["method_name"] = this.name;
        }
        if (hookOpts.thread !== false) {
            event["thread_id"] = Process.getCurrentThreadId();
        }
        if (hookOpts.args !== false) {
            event["result"] = pretty2Json(ret);
        }
        if (hookOpts.stack !== false) {
            const stack = event["stack"] = [];
            const backtracer = hookOpts.backtracer === "accurate" ? Backtracer.ACCURATE : Backtracer.FUZZY;
            const elements = Thread.backtrace(this.context, backtracer);
            for (let i = 0; i < elements.length; i++) {
                stack.push(getDescFromAddress(elements[i], hookOpts.symbol !== false));
            }
        }
        Log.event(event);
    }

    return result;
}

export function getDebugSymbolFromAddress(pointer: NativePointer): DebugSymbol {
    const key = pointer.toString();
    if ($debugSymbolAddressCaches[key] === void 0) {
        $debugSymbolAddressCaches[key] = DebugSymbol.fromAddress(pointer);
    }
    return $debugSymbolAddressCaches[key];
}

export function getDescFromAddress(pointer: NativePointer, symbol: boolean) {
    if (symbol) {
        const debugSymbol = getDebugSymbolFromAddress(pointer);
        if (debugSymbol != null) {
            return debugSymbol.toString();
        }
    }
    const module = $moduleMap.find(pointer);
    if (module != null) {
        return `${pointer} ${module.name}!${pointer.sub(module.base)}`;
    }
    return `${pointer}`;
}
