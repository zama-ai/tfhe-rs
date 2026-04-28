import * as Comlink from "comlink";
import * as pkg from "../pkg-client/tfhe.js";
import { initRuntime } from "../shared/init.js";
import { x86CompatBench, x86CompatTest } from "./tests/x86-compat.js";

async function main() {
  await initRuntime(pkg);

  // Use Comlink.proxy() to ensure the object is proxied, not copied.
  // This allows functions to be called across the worker boundary.
  return Comlink.proxy({
    x86CompatTest,
    x86CompatBench,
  });
}

// When loaded as a worker, expose via Comlink.
Comlink.expose({
  demos: main(),
});
