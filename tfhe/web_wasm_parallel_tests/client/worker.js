import * as Comlink from "comlink";
import { initRuntime } from "../shared/init.js";
import { makeFixtureDemos } from "../shared/fixture-demos.js";

const ready = (async () => {
  const pkg = await import(/* webpackIgnore: true */ "/pkg-client/tfhe.js");
  await initRuntime(pkg);
  return makeFixtureDemos(pkg);
})();

Comlink.expose({
  demos: ready.then((demos) => Comlink.proxy(demos)),
  names: ready.then((demos) => Object.keys(demos)),
});
