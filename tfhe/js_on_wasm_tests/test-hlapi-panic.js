const test = require('node:test');
const assert = require('node:assert').strict;
const {
    init_panic_hook,
    TfheClientKey,
    TfheConfigBuilder,
    FheUint8,
} = require("../pkg/tfhe.js");


const U256_MAX = BigInt("115792089237316195423570985008687907853269984665640564039457584007913129639935");
const U128_MAX = BigInt("340282366920938463463374607431768211455");
const U32_MAX = 4294967295;

// This is useful to debug test
//
// Note that the test hlapi_panic
// purposefully creates a panic, to some panic message
// will be printed and tess will be ok
init_panic_hook();

// Here integers are not enabled
// but we try to use them, so an error should be returned
// as the underlying panic should have been trapped

// Put in its own file as some async access is causing panics, to be investigated
test('hlapi_panic', (t) => {
    let config = TfheConfigBuilder.all_disabled()
        .build();

    let clientKey = TfheClientKey.generate(config);

    let clear = 73;

    console.log("\nThe following log is an expected error log:\n=======================\n")

    try {
        let _ = FheUint8.encrypt_with_client_key(clear, clientKey);
        assert(false);
    } catch (e) {
        assert(true);
    }
});
