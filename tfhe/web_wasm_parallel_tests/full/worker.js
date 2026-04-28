import * as Comlink from "comlink";
import { initRuntime } from "../shared/init.js";
import { makeFullDemos } from "./demos.js";

const ready = (async () => {
  const pkg = await import(/* webpackIgnore: true */ "/pkg/tfhe.js");
  await initRuntime(pkg);
  return makeFullDemos(pkg);
})();

Comlink.expose({
  demos: ready.then((demos) => Comlink.proxy(demos)),
  names: ready.then((demos) => Object.keys(demos)),
});
