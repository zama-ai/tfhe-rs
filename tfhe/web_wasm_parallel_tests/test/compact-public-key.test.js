import { runTestAttachedToButton } from "./common.mjs";

// it("Compact Public Key Test Big 32 Bit", async () => {
//   await runTestAttachedToButton("compactPublicKeyTest32BitBig");
// });

// it("Compact Public Key Test Small 32 Bit", async () => {
//   await runTestAttachedToButton("compactPublicKeyTest32BitSmall");
// });

// it("Compact Public Key Test Small 256 Bit", async () => {
//   await runTestAttachedToButton("compactPublicKeyTest256BitSmall");
// });

// it("Compact Public Key Test Big 256 Bit", async () => {
//   await runTestAttachedToButton("compactPublicKeyTest256BitBig");
// });

// it("Compressed Compact Public Key Test Small 256 Bit", async () => {
//   await runTestAttachedToButton("compressedCompactPublicKeyTest256BitSmall");
// });

// it("Compressed Compact Public Key Test Big 256 Bit", async () => {
//   await runTestAttachedToButton("compressedCompactPublicKeyTest256BitBig");
// });

it(
  "Compact Public Key Bench Big 64 Bit With ZeroKnowledgeBench",
  async () => {
    await runTestAttachedToButton("compactPublicKeyZeroKnowledgeBench");
  },
  1_000_000 * 1000,
); // 20 minutes timeout
