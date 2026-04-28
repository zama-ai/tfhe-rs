import * as Comlink from "comlink";
import * as pkg from "../pkg/tfhe.js";
import { initRuntime } from "../shared/init.js";
import { compressedPublicKeyTest, publicKeyTest } from "./tests/public-key.js";
import {
  compactPublicKeyWithCastingTest256Bit,
  compressedCompactPublicKeyTest256BitBig,
  compressedCompactPublicKeyTest256BitSmall,
  compressedCompactPublicKeyWithCastingTest256Bit,
} from "./tests/compact-key.js";
import { compactPublicKeyZeroKnowledgeTest } from "./tests/zk.js";
import { x86CompatBench, x86CompatTest } from "./tests/x86-compat.js";
import {
  compactPublicKeyBench256BitBig,
  compactPublicKeyBench256BitSmall,
  compactPublicKeyBench32BitBig,
  compactPublicKeyBench32BitSmall,
} from "./benches/compact-key.js";
import {
  compressedServerKeyBenchMessage1Carry1,
  compressedServerKeyBenchMessage2Carry2,
} from "./benches/server-key.js";
import { compactPublicKeyZeroKnowledgeBench } from "./benches/zk.js";

async function main() {
  await initRuntime(pkg);

  // Use Comlink.proxy() to ensure the object is proxied, not copied.
  // This allows functions to be called across the worker boundary.
  return Comlink.proxy({
    publicKeyTest,
    compressedPublicKeyTest,
    compressedCompactPublicKeyTest256BitSmall,
    compressedCompactPublicKeyTest256BitBig,
    compactPublicKeyZeroKnowledgeTest,
    compactPublicKeyBench32BitBig,
    compactPublicKeyBench32BitSmall,
    compactPublicKeyBench256BitBig,
    compactPublicKeyBench256BitSmall,
    compactPublicKeyWithCastingTest256Bit,
    compressedCompactPublicKeyWithCastingTest256Bit,
    compressedServerKeyBenchMessage1Carry1,
    compressedServerKeyBenchMessage2Carry2,
    compactPublicKeyZeroKnowledgeBench,
    x86CompatTest,
    x86CompatBench,
  });
}

// When loaded as a worker, expose via Comlink.
Comlink.expose({
  demos: main(),
});
