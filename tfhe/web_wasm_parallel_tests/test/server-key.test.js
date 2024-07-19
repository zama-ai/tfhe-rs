import { runTestAttachedToButton } from "./common.mjs";

it("Server Key Bench 1_1", async () => {
  await runTestAttachedToButton("compressedServerKeyBenchMessage1Carry1");
}, 600000); // 10 minutes timeout

it("Server Key Bench 2_2", async () => {
  await runTestAttachedToButton("compressedServerKeyBenchMessage2Carry2");
}, 600000); // 10 minutes timeout
