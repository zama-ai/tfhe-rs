import { threads } from 'wasm-feature-detect';
import * as Comlink from 'comlink';


function setButtonsDisabledState(buttonIds, state) {
    for (let id of buttonIds) {
        let btn = document.getElementById(id);
        if (btn) {
            btn.disabled = state;
        }
    }
}

async function setup() {
    let supportsThreads = await threads()
    if (!supportsThreads) {
        console.error("This browser does not support threads")
        return
    }

    const worker = new Worker(
        new URL("worker.js", import.meta.url),
        {type: 'module'}
    );
    const demos = await Comlink.wrap(worker).demos;

    const demoNames = ['publicKeyTest', 'compressedPublicKeyTest']

    function setupBtn(id) {
        // Handlers are named in the same way as buttons.
        let fn = demos[id];

        let button = document.getElementById(id);
        if (button === null) {
            return null;
        }

        // Assign onclick handler + enable the button.
        Object.assign(button, {
            onclick: async () => { 
                document.getElementById("loader").hidden = false
                document.getElementById("testSuccess").checked = false
                setButtonsDisabledState(demoNames, true);

                try {
                    await fn()
                    document.getElementById("testSuccess").checked = true
                } catch (error) {
                    console.error(error)
                    document.getElementById("testSuccess").checked = false
                }
                document.getElementById("loader").hidden = true
                setButtonsDisabledState(demoNames, false);
            },
            disabled: false
        });

        return button;
    }

    for (let demo of demoNames) {
        setupBtn(demo)
    }
}


setup()


