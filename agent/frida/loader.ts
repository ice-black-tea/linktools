interface Parameters {
    [name: string]: any;
}

interface Script {
    filename: string;
    source: string;
}

export class ScriptLoader {

    load(scripts: Script[], parameters: Parameters) {
        for (const script of scripts) {
            try {
                let name = script.filename;
                name = name.replace(/[\/\\]/g, '$');
                name = name.replace(/[^A-Za-z0-9_$]+/g, "_");
                name = `fn_${name}`.substring(0, 255);
                const func = (0, eval)(
                    `(function ${name}(parameters) {${script.source}\n})\n` +
                    `//# sourceURL=${script.filename}`
                )
                func(parameters);
            } catch (e) {
                let message = e.hasOwnProperty("stack") ? e.stack : e;
                throw new Error(`Unable to load ${script.filename}: ${message}`);
            }
        }
    }
}