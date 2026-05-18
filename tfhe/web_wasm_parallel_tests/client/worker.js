import * as Comlink from "comlink";
import * as pkg from "../pkg-client/tfhe.js";
import { initRuntime } from "../shared/init.js";
import {
  fixtureEncryptProveBench,
  fixtureEncryptProveTest,
} from "./tests/fixture-encrypt-prove.js";

async function main() {
  await initRuntime(pkg);

  // Use Comlink.proxy() to ensure the object is proxied, not copied.
  // This allows functions to be called across the worker boundary.
  return Comlink.proxy({
    fixtureEncryptProveTest,
    fixtureEncryptProveBench,
  });
}

// When loaded as a worker, expose via Comlink.
Comlink.expose({
  demos: main(),
});
