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
                eval(script.source);
            } catch (e) {
                let message = e.hasOwnProperty("stack") ? e.stack : e;
                throw new Error(`Unable to load ${script.filename}: ${message}`);
            }
        }
    }
}