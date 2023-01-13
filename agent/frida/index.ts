////////////////////////////////////////////////////////////////////////
// emitter
////////////////////////////////////////////////////////////////////////


class EmitterWorker {

    private pendingEvents: any[] = [];
    private flushTimer: any = null;

    emit(type: string, message: any, data?: ArrayBuffer | number[] | null) {
        const event = {};
        event[type] = message;

        if (data == null) {
            // 如果data为空，则加到pending队列，打包一起发送
            this.pendingEvents.push(event);
            if (this.pendingEvents.length >= 50) {
                // 当短时间积累的事件太多，可能会出现卡死的情况
                // 所以设置一个pending队列的阈值
                this.flush();
            } else if (this.flushTimer === null) {
                this.flushTimer = setTimeout(this.flush, 50);
            }
        } else {
            // data不为空，就不能一次性发送多个event
            // 立即把pending队列的发过去，然后发送带data的message
            this.flush();
            send({ $events: [event] }, data);
        }
    }

    private flush = () => {
        if (this.flushTimer !== null) {
            clearTimeout(this.flushTimer);
            this.flushTimer = null;
        }

        if (this.pendingEvents.length === 0) {
            return;
        }

        const events = this.pendingEvents;
        this.pendingEvents = [];

        send({ $events: events });
    };
}


class Emitter {

    emit(message: any, data?: ArrayBuffer | number[] | null) {
        emitterWorker.emit("msg", message, data);
    }
}


////////////////////////////////////////////////////////////////////////
// log
////////////////////////////////////////////////////////////////////////

class Log {

    DEBUG = 1;
    INFO = 2;
    WARNING = 3;
    ERROR = 4;
    private $level = this.INFO;

    get level(): number {
        return this.$level;
    }

    setLevel(level: number) {
        this.$level = level;
        this.d("Set log level: " + level);
    }

    d(message: any, data?: ArrayBuffer | number[] | null) {
        if (this.$level <= this.DEBUG) {
            emitterWorker.emit("log", { level: "debug", message: message }, data);
        }
    }

    i(message: any, data?: ArrayBuffer | number[] | null) {
        if (this.$level <= this.INFO) {
            emitterWorker.emit("log", { level: "info", message: message }, data);
        }
    }

    w(message: any, data?: ArrayBuffer | number[] | null) {
        if (this.$level <= this.WARNING) {
            emitterWorker.emit("log", { level: "warning", message: message }, data);
        }
    }

    e(message: any, data?: ArrayBuffer | number[] | null) {
        if (this.$level <= this.ERROR) {
            emitterWorker.emit("log", { level: "error", message: message }, data);
        }
    }
}


////////////////////////////////////////////////////////////////////////
// script loader
////////////////////////////////////////////////////////////////////////

interface Parameters {
    [name: string]: any;
}

interface Script {
    filename: string;
    source: string;
}

class ScriptLoader {

    load(scripts: Script[], parameters: Parameters) {
        Object.defineProperties(globalThis, {
            parameters: {
                configurable: true,
                enumerable: true,
                value: parameters
            }
        });

        for (const script of scripts) {
            try {
                (1, eval)(script.source);
            } catch (e) {
                let message = e.hasOwnProperty("stack") ? e.stack : e;
                throw new Error(`Unable to load ${script.filename}: ${message}`);
            }
        }
    }
}


////////////////////////////////////////////////////////////////////////
// local variables
////////////////////////////////////////////////////////////////////////

const scriptLoader = new ScriptLoader();
const emitterWorker = new EmitterWorker();
const debugSymbolAddressCache: { [key: string]: DebugSymbol; } = {};

rpc.exports = {
    loadScripts: scriptLoader.load.bind(scriptLoader),
};


////////////////////////////////////////////////////////////////////////
// global variables
////////////////////////////////////////////////////////////////////////

import { CHelper } from "./lib/c"
import { JavaHelper } from "./lib/java";
import { AndroidHelper } from "./lib/android";
import { ObjCHelper } from "./lib/objc";
import { IOSHelper } from "./lib/ios";

const emitter = new Emitter();
const log = new Log();
const cHelper = new CHelper();
const javaHelper = new JavaHelper();
const androidHelper = new AndroidHelper();
const objCHelper = new ObjCHelper();
const iosHelper = new IOSHelper();


declare global {
    const Emitter: Emitter;
    const Log: Log;
    const CHelper: CHelper;
    const JavaHelper: JavaHelper;
    const AndroidHelper: AndroidHelper;
    const ObjCHelper: ObjCHelper;
    const IOSHelper: IOSHelper;
    const parameters: Parameters;
    function ignoreError<T>(fn: () => T): T;
    function ignoreError<T>(fn: () => T, defautValue: T): T;
    function parseBoolean(value: string | boolean);
    function parseBoolean(value: string | boolean, defaultValue: boolean);
    function pretty2String(obj: any): any;
    function pretty2Json(obj: any): any;
    function getDebugSymbolFromAddress(pointer: NativePointer): DebugSymbol;
}


Object.defineProperties(globalThis, {
    Emitter: {
        enumerable: true,
        value: emitter
    },
    Log: {
        enumerable: true,
        value: log
    },
    CHelper: {
        enumerable: true,
        value: cHelper
    },
    JavaHelper: {
        enumerable: true,
        value: javaHelper
    },
    AndroidHelper: {
        enumerable: true,
        value: androidHelper
    },
    ObjCHelper: {
        enumerable: true,
        value: objCHelper
    },
    IOSHelper: {
        enumerable: true,
        value: iosHelper
    },
    ignoreError: {
        enumerable: false,
        value: function <T>(fn: () => T, defautValue: T = void 0): T {
            try {
                return fn();
            } catch (e) {
                log.d("Catch ignored error. " + e);
                return defautValue;
            }
        }
    },
    parseBoolean: {
        enumerable: false,
        value: function (value: string | boolean, defaultValue: boolean = void 0) {
            if (typeof (value) === "boolean") {
                return value;
            }
            if (typeof (value) === "string") {
                const lower = value.toLowerCase();
                if (lower === "true") {
                    return true;
                } else if (lower === "false") {
                    return false;
                }
            }
            return defaultValue;
        }
    },
    pretty2String: {
        enumerable: false,
        value: function (obj: any): string {
            if (typeof obj !== "string") {
                obj = pretty2Json(obj);
            }
            return JSON.stringify(obj);
        }
    },
    pretty2Json: {
        enumerable: false,
        value: function (obj: any): any {
            if (!(obj instanceof Object)) {
                return obj;
            }
            if (Array.isArray(obj)) {
                let result = [];
                for (let i = 0; i < obj.length; i++) {
                    result.push(pretty2Json(obj[i]));
                }
                return result;
            }
            if (Java.available) {
                if (javaHelper.isJavaObject(obj)) {
                    return javaHelper.objectClass.toString.apply(obj);
                }
            }
            return ignoreError(() => obj.toString());
        }
    },
    getDebugSymbolFromAddress: {
        enumerable: false,
        value: function(pointer: NativePointer): DebugSymbol {
            const key = pointer.toString();
            if (debugSymbolAddressCache[key] === void 0) {
                debugSymbolAddressCache[key] = DebugSymbol.fromAddress(pointer);
            }
            return debugSymbolAddressCache[key];
        }
    }
});
