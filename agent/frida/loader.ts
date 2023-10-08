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
                const name = `exec_${script.filename.replace(/[^A-Za-z0-9_]+/gi, "_")}`;
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