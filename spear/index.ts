import { JavaHelper } from "./lib/java";
import { AndroidHelper } from "./lib/android";
import { ObjCHelper } from "./lib/objc";


declare global {
    const Log: Log;
    const JavaHelper: JavaHelper;
    const AndroidHelper: AndroidHelper;
    const ObjCHelper: ObjCHelper;
    const parameters: Parameters;
    function ignoreError<T>(fn: () => T, defautValue: T): T;
}


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
                enumerable: true,
                value: parameters
            }
        });

        for (const script of scripts) {
            try {
                (1, eval)(script.source);
            } catch (e) {
                throw new Error(`Unable to load ${script.filename}: ${e.stack}`);
            }
        }
    }
}

const loader = new ScriptLoader();

rpc.exports = {
    loadScripts: loader.load.bind(loader),
};


class Log {

    debug = 1;
    info = 2;
    warning = 3;
    error = 4;
    private $level = this.info;

    get level(): number {
        return this.$level;
    }

    setLevel(level: number) {
        this.$level = level;
        this.d("Set log level: " + level);
    }

    d(data: any, tag: string = null) {
        if (this.$level <= this.debug) {
            send({ log: { level: "debug", tag: tag, message: data } });
        }
    }

    i(data: any, tag: string = null) {
        if (this.$level <= this.info) {
            send({ log: { level: "info", tag: tag, message: data } });
        }
    }

    w(data: any, tag: string = null) {
        if (this.$level <= this.warning) {
            send({ log: { level: "warning", tag: tag, message: data } });
        }
    }

    e(data: any, tag: string = null) {
        if (this.$level <= this.error) {
            send({ log: { level: "error", tag: tag, message: data } });
        }
    }
}


Object.defineProperties(globalThis, {
    Log: {
        enumerable: true,
        value: new Log()
    },
    JavaHelper: {
        enumerable: true,
        value: new JavaHelper()
    },
    AndroidHelper: {
        enumerable: true,
        value: new AndroidHelper()
    },
    ObjCHelper: {
        enumerable: true,
        value: new ObjCHelper()
    },
    ignoreError: {
        enumerable: false,
        value: function <T>(fn: () => T, defautValue: T = undefined): T {
            try {
                return fn();
            } catch {
                return defautValue;
            }
        }
    }
});
