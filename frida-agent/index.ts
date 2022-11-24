////////////////////////////////////////////////////////////////////////
// emitter
////////////////////////////////////////////////////////////////////////


class Event {
    type: string = null;
    message: string = null;
    data: ArrayBuffer | number[] | null = null;
    constructor(type: string, message: string, data: ArrayBuffer | number[] | null) {
        this.type = type;
        this.message = message;
        this.data = data;
    }
}


class Emitter {

    private pendingEvents: Event[] = [];
    private flushTimer: any = null;

    emit(type: string, message: any, data?: ArrayBuffer | number[] | null) {
        this.pendingEvents.push(new Event(type, message, data));

        if (this.flushTimer === null) {
            this.flushTimer = setTimeout(this.flush, 50);
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

        var messages = [];
        while (events.length > 0) {
            const event = events.shift();
            if (event.data != null) {
                // 如果data字段不为空，必须得单独发，同时需要把之前的消息发送了
                if (messages.length > 0) {
                    send({ $events: messages });
                    messages = [];
                }
                send({ $event: event }, event.data);
            } else {
                // 只是把消息放到待发送队列
                const message = {};
                message[event.type] = event.message;
                messages.push(message);
            }
        }

        if (messages.length > 0) {
            send({ $events: messages });
            messages = null;
        }
    };
}


class EmitterWrapper {

    emit(message: any, data?: ArrayBuffer | number[] | null) {
        $emitter.emit("msg", message, data);
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
            $emitter.emit("log", { level: "debug", message: message }, data);
        }
    }

    i(message: any, data?: ArrayBuffer | number[] | null) {
        if (this.$level <= this.INFO) {
            $emitter.emit("log", { level: "info", message: message }, data);
        }
    }

    w(message: any, data?: ArrayBuffer | number[] | null) {
        if (this.$level <= this.WARNING) {
            $emitter.emit("log", { level: "warning", message: message }, data);
        }
    }

    e(message: any, data?: ArrayBuffer | number[] | null) {
        if (this.$level <= this.ERROR) {
            $emitter.emit("log", { level: "error", message: message }, data);
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

const loader = new ScriptLoader();

rpc.exports = {
    loadScripts: loader.load.bind(loader),
};


////////////////////////////////////////////////////////////////////////
// global variables
////////////////////////////////////////////////////////////////////////

import { CHelper } from "./lib/c"
import { JavaHelper } from "./lib/java";
import { AndroidHelper } from "./lib/android";
import { ObjCHelper } from "./lib/objc";
import { IOSHelper } from "./lib/ios";


const $emitter = new Emitter();
const emitter = new EmitterWrapper();
const log = new Log();
const cHelper = new CHelper();
const javaHelper = new JavaHelper();
const androidHelper = new AndroidHelper();
const objCHelper = new ObjCHelper();
const iosHelper = new IOSHelper();


declare global {
    const Emitter: EmitterWrapper;
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
        value: function <T>(fn: () => T, defautValue: T = undefined): T {
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
        value: function (value: string | boolean, defaultValue: boolean = undefined) {
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
            obj = pretty2Json(obj);
            return obj instanceof Object ? JSON.stringify(obj) : obj;
        }
    },
    pretty2Json: {
        enumerable: false,
        value: function (obj: any): any {
            if (!(obj instanceof Object)) {
                return obj;
            }
            if (Array.isArray(obj) || javaHelper.isArray(obj)) {
                let result = [];
                for (let i = 0; i < obj.length; i++) {
                    result.push(pretty2Json(obj[i]));
                }
                return result;
            }
            return ignoreError(() => obj.toString());
        }
    }
});
