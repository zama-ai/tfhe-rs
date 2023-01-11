# Tutorial

## Using the JS on WASM API

Welcome to this TFHE-rs JS on WASM API tutorial!

TFHE-rs uses WASM to expose a JS binding to the client-side primitives, like key generation and encryption, of the Boolean and shortint modules.

There are several limitations at this time. Due to a lack of threading support in WASM, key 
generation can be too slow to be practical for bigger parameter sets.

Some parameter sets lead to FHE keys that are too big to fit in the 2GB memory space of WASM. 
This means that some parameters sets are virtually unusable.

## First steps using TFHE-rs JS on WASM API

### Setting-up TFHE-rs JS on WASM API for use in nodejs programs.

To build the JS on WASM bindings for TFHE-rs, you will first need to install [`wasm-pack`](https://rustwasm.github.io/wasm-pack/) in addition to a compatible (>= 1.65) [`rust toolchain`](https://rustup.rs/).

Then, in a shell run the following to clone the TFHE-rs repo (one may want to checkout a 
specific tag, here the default branch is used for the build):

```shell
$ git clone https://github.com/zama-ai/tfhe-rs.git
Cloning into 'tfhe-rs'...
...
Resolving deltas: 100% (3866/3866), done.
$ cd tfhe-rs
$ cd tfhe
$ rustup run wasm-pack build --release --target=nodejs --features=boolean-client-js-wasm-api,shortint-client-js-wasm-api
[INFO]: Compiling to Wasm...
...
[INFO]: :-) Your wasm pkg is ready to publish at ...
```

The command above targets nodejs. A binding for a web browser can be generated as well using 
`--target=web`.  This use case will not be discussed in this tutorial.

Both Boolean and shortint features are enabled here but it's possible to use one without the other.

After the build, a new directory ***pkg*** is present in the `tfhe` directory.

```shell
$ ls pkg
LICENSE  index.html  package.json  tfhe.d.ts  tfhe.js  tfhe_bg.txt  tfhe_bg.wasm  tfhe_bg.wasm.d.ts
$
```

### Commented code to generate keys for shortint and encrypt a ciphertext

WARNING: Be sure to update the path of the required clause in the example below for the TFHE 
package that was just built.

```js
// Here import assert to check the decryption went well and panic otherwise
const assert = require('node:assert').strict;
// Import the Shortint module from the TFHE-rs package generated earlier
const { Shortint } = require("/path/to/built/tfhe/pkg");

function shortint_example() {
    // Get pre-defined parameters from the shortint module to manage messages with 4 bits of useful
    // information in total (2 bits of "message" and 2 bits of "carry")
    let params = Shortint.get_parameters(2, 2);
    // Create a new secret ClientKey, this must not be shared
    console.log("Generating client keys...")
    let cks = Shortint.new_client_key(params);
    // Encrypt 3 in a ciphertext
    console.log("Encrypting 3...")
    let ct = Shortint.encrypt(cks, BigInt(3));

    // Demonstrate ClientKey serialization (for example saving it on disk on the user device)
    let serialized_cks = Shortint.serialize_client_key(cks);
    // Deserialization
    let deserialized_cks = Shortint.deserialize_client_key(serialized_cks);

    // Demonstrate ciphertext serialization to send over the network
    let serialized_ct = Shortint.serialize_ciphertext(ct);
    // Deserialize a ciphertext received over the network for example
    let deserialized_ct = Shortint.deserialize_ciphertext(serialized_ct);

    // Decrypt with the deserialized objects
    console.log("Decrypting ciphertext...")
    let decrypted = Shortint.decrypt(deserialized_cks, deserialized_ct);
    // Check decryption works as expected
    assert.deepStrictEqual(decrypted, BigInt(3));
    console.log("Decryption successful!")

    // Generate public evaluation keys, also called ServerKey
    console.log("Generating compressed ServerKey...")
    let sks = Shortint.new_compressed_server_key(cks);

    // Can be serialized to send over the network to the machine doing the evaluation
    let serialized_sks = Shortint.serialize_compressed_server_key(sks);
    let deserialized_sks = Shortint.deserialize_compressed_server_key(serialized_sks);
    console.log("All done!")
}

shortint_example();
```

The `example.js` script can then be run using [`node`](https://nodejs.org/) like so:

```shell
$ node example.js
Generating client keys...
Encrypting 3...
Decrypting ciphertext...
Decryption successful!
Generating compressed ServerKey...
All done!
$
```
