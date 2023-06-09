import { runTestAttachedToButton } from "./common.mjs";


it('Compact Public Key Bench Big 32 Bit', async () => {
    await runTestAttachedToButton('compactPublicKeyBench32BitBig')
});

it('Compact Public Key Bench Small 32 Bit', async () => {
    await runTestAttachedToButton('compactPublicKeyBench32BitSmall')
});

it('Compact Public Key Bench Big 256 Bit', async () => {
    await runTestAttachedToButton('compactPublicKeyBench256BitBig')
});

it('Compact Public Key Bench Small 256 Bit', async () => {
    await runTestAttachedToButton('compactPublicKeyBench256BitSmall')
});
