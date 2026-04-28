# JS on WASM API

This document outlines how to use the **TFHE-rs** WebAssembly (WASM) client API for key generation, encryption, and decryption, providing setup examples for Node.js and web browsers.

**TFHE-rs** supports WASM client API, which includes functionality for key generation, encryption, and decryption. However, it does not support FHE computations.

The packages differ in two ways: the runtime they target, and how much of the API they include.

For the runtime:

* Node.js, for Node.js applications or packages.
* The browser, where parallelism is optional and comes in two flavors: standard `SharedArrayBuffer` threads, which need cross-origin isolation (COOP/COEP headers), or a Service Worker coordinator that works without it.

For the API:

* The full package exposes the whole client API (Boolean, shortint and integer) and compact public-key encryption.
* The client package is a smaller build with only compact encryption and zero-knowledge proofs, for when all you do on the client side is build and prove compact ciphertext lists.

## Client (compact) API

The client package (the `build_*_client` targets) keeps only what a client needs to generate keys and build compact ciphertext lists:

**Keys and configuration**

* `init_panic_hook()`: forward Rust panics to the JS console.
* `TfheConfig`: cryptographic configuration, via `TfheConfig.default()`.
* `TfheClientKey`: the secret key (`generate`, `generate_with_seed`, `safe_serialize` / `safe_deserialize`).
* `TfheCompactPublicKey`: the public encryption key (`new`, `safe_serialize` / `safe_deserialize` / `safe_deserialize_conformant`).

**Compact encryption**

* `CompactCiphertextListBuilder`: push clear values (`push_u2` to `push_u2048`, `push_i2` to `push_i2048`, `push_boolean`), then call `build`, `build_packed` or `build_packed_seeded`.
* `CompactCiphertextList`: the built list, obtained from `CompactCiphertextList.builder(publicKey)`.
* `FheTypes`: enum identifying the type of each element.

**Zero-knowledge proofs** (require the `zk-pok` feature)

* `CompactPkeCrs`: the common reference string (`from_config`, `safe_serialize` / `safe_deserialize`).
* `ProvenCompactCiphertextList`: a list built together with a proof through `CompactCiphertextListBuilder.build_with_proof_packed(...)`; supports `len`, `is_empty`, `get_kind_of`, `safe_serialize` / `safe_deserialize`.
* `ZkComputeLoad`: `Proof` or `Verify`.

There is no server key, and no way to expand or decrypt ciphertexts; the Boolean and shortint modules are gone too. Reach for the full package when you need any of that.

## Node.js

Example:

```javascript
const {
  init_panic_hook,
  ShortintParametersName,
  ShortintParameters,
  TfheClientKey,
  TfheCompactPublicKey,
  TfheCompressedServerKey,
  TfheConfigBuilder,
  CompactCiphertextList
} = require("/path/to/built/pkg/tfhe.js");

const assert = require("node:assert").strict;

function fhe_uint32_example() {
  // Makes it so that if a rust thread panics,
  // the error message will be displayed in the console
  init_panic_hook();

  const U32_MAX = 4294967295;

  const block_params = new ShortintParameters(ShortintParametersName.V1_6_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS_GAUSSIAN_2M64);
  let config = TfheConfigBuilder.default()
      .build();

  let clientKey = TfheClientKey.generate(config);
  let compressedServerKey = TfheCompressedServerKey.new(clientKey);
  let publicKey = TfheCompactPublicKey.new(clientKey);

  let values = [0, 1, 2394, U32_MAX];
  let builder = CompactCiphertextList.builder(publicKey);
  for (let i = 0; i < values.length; i++) {
    builder.push_u32(values[i]);
  }

  let compact_list = builder.build();

  let serialized_list = compact_list.serialize();
  let deserialized_list = CompactCiphertextList.deserialize(serialized_list);
  let encrypted_list = deserialized_list.expand();
  assert.deepStrictEqual(encrypted_list.len(), values.length);

  for (let i = 0; i < values.length; i++)
  {
      let decrypted = encrypted_list.get_uint32(i).decrypt(clientKey);
      assert.deepStrictEqual(decrypted, values[i]);
  }
}

fhe_uint32_example();

```

## Web

When using the Web WASM target, you should call an additional `init` function. With parallelism enabled, you need to call another additional `initThreadPool` function.

Example:

```js
import init, {
    initThreadPool, // only available with parallelism
    init_panic_hook,
    ShortintParametersName,
    ShortintParameters,
    TfheClientKey,
    TfhePublicKey,
} from "./pkg/tfhe.js";

async function example() {
    await init()
    await initThreadPool(navigator.hardwareConcurrency);
    await init_panic_hook();

    const block_params = new ShortintParameters(ShortintParametersName.V1_6_PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS_GAUSSIAN_2M64);
    // ....
}
```

## Web (cross-origin parallelism)

Standard multi-threading in WASM requires [cross-origin isolation](https://developer.mozilla.org/en-US/docs/Web/API/Window/crossOriginIsolated) (COOP/COEP headers) to enable `SharedArrayBuffer`. Some deployment environments cannot set these headers (e.g., when embedding in third-party pages or certain hosting platforms).

**TFHE-rs** provides an alternative parallelism mode that works **without cross-origin isolation** by using a Service Worker coordinator and a message-passing-based worker pool. This mode is used to accelerate **zero-knowledge proof** computation in the browser.

### Setup

Cross-origin parallelism requires a **coordinator Service Worker** (`coordinator.js`) to be served at the root of your application. After compiling with `make build_web_js_api`, the `pkg/` directory will contain a `coordinator.js` module; you can simply copy it at the root of your web server.

### Initialization from the main thread

If your application runs entirely from the main page (no dedicated Web Worker), you can initialize everything in one call:

```js
import init, {
    init_panic_hook,
    init_cross_origin_worker_pool,
} from "./pkg/tfhe.js";

async function setup() {
    await init();
    await init_cross_origin_worker_pool(
        "/coordinator.js",   // URL to the coordinator Service Worker
        null,                // number of workers (null = auto-detect)
    );
    await init_panic_hook();
    // TFHE-rs is ready, ZK proof operations will run in parallel
}
```

Since the main thread JS cannot block, you need to build the list using the dedicated async method:

```js
let list = await builder.build_with_proof_packed_async(
      crs,
      metadata,
      ZkComputeLoad.Proof,
);
```

### Initialization with a dedicated Web Worker (Comlink pattern)

To reduce the overhead of synchronization between workers, it is advised to offload the encryption process to a Web Worker using a library like [Comlink](https://github.com/GoogleChromeLabs/comlink). In this case, the coordinator must be registered on the **main thread** before the worker initializes the pool:

**Main thread (`index.js`):**

```js
import init, { register_cross_origin_coordinator } from "./pkg/tfhe.js";

async function setup() {
    await init();
    // Register the coordinator Service Worker from the main thread
    await register_cross_origin_coordinator("/sw.js");

    // Then create a Web Worker that will call init_cross_origin_worker_pool_from_worker
    const worker = new Worker(new URL("./worker.js", import.meta.url), {
        type: "module",
    });
    // ...
}
```

**Web Worker (`worker.js`):**

```js
import init, {
    init_panic_hook,
    init_cross_origin_worker_pool_from_worker,
} from "./pkg/tfhe.js";

async function main() {
    await init();
    await init_cross_origin_worker_pool_from_worker();
    await init_panic_hook();
    // TFHE-rs is ready, ZK proof operations will run in parallel
}
```

### Runtime detection

You can detect at runtime whether cross-origin isolation is available and fall back to cross-origin workers automatically:

```js
import { threads } from "wasm-feature-detect";
import init, {
    initThreadPool,
    init_cross_origin_worker_pool,
} from "./pkg/tfhe.js";

await init();
let supportsThreads = await threads();
if (supportsThreads) {
    // Standard SharedArrayBuffer parallelism
    await initThreadPool(navigator.hardwareConcurrency);
} else {
    // Fallback: cross-origin worker pool
    await init_cross_origin_worker_pool("/sw.js");
}
```

## Compiling the WASM API

Use the provided Makefile in the **TFHE-rs** repository to compile for the desired target. Each command produces a package in `tfhe/pkg`.

**Full API** (Boolean, shortint and integer):

* `make build_node_js_api`: Node.js API
* `make build_web_js_api`: browser API, sequential or cross-origin parallelism
* `make build_web_js_api_parallel`: browser API with `SharedArrayBuffer` parallelism (requires cross-origin isolation)

**Client (compact) API** (compact encryption + zero-knowledge proofs only, lighter package):

* `make build_node_js_api_client`: Node.js client API
* `make build_web_js_api_client`: browser client API, sequential or cross-origin parallelism
* `make build_web_js_api_parallel_client`: browser client API with `SharedArrayBuffer` parallelism

The compiled WASM packages are located in `tfhe/pkg` (the output directory of the web client builds can be overridden with the `WEB_CLIENT_OUT_DIR` variable).

{% hint style="info" %}
The packages are also published on npm:

| Package | Build command | Description |
| --- | --- | --- |
| `tfhe` | `build_web_js_api_parallel` | Browser, full API, `SharedArrayBuffer` parallelism |
| `tfhe-compat` | `build_web_js_api` | Browser, full API, cross-origin parallelism |
| `node-tfhe` | `build_node_js_api` | Node.js, full API |
| `tfhe-client` | `build_web_js_api_parallel_client` | Browser, client API, `SharedArrayBuffer` parallelism |
| `tfhe-client-compat` | `build_web_js_api_client` | Browser, client API, cross-origin parallelism |
{% endhint %}

### Extra steps for web bundlers

When using the browser API _with parallelism_, some extra step might be needed depending on the bundler used:

#### Usage with Webpack

If you're using Webpack v5 (version >= 5.25.1), you don't need to do anything special, as it already supports [bundling Workers](https://webpack.js.org/guides/web-workers/) out of the box.

#### Usage with Parcel

Parcel v2 also recognises the used syntax and works out of the box.

#### Usage with Rollup

For Rollup, you'll need [`@surma/rollup-plugin-off-main-thread`](https://github.com/surma/rollup-plugin-off-main-thread) plugin (version >= 2.1.0) which brings the same functionality and was tested with this crate.

Alternatively, you can use [Vite](https://vitejs.dev/) which has necessary plugins built-in.

(Taken from [RReverser/wasm-bindgen-rayon](https://github.com/RReverser/wasm-bindgen-rayon?tab=readme-ov-file#usage-with-various-bundlers))

## Using the JS on WASM API

**TFHE-rs** uses WASM to provide a JavaScript (JS) binding to the client-side primitives, like key generation and encryption within the Boolean, shortint and integer modules.

Currently, there are several limitations. Due to a lack of threading support in WASM, key generation can be too slow to be practical for bigger parameter sets.

Some parameter sets lead to the FHE keys exceeding the 2GB memory limit of WASM, making these parameter sets virtually unusable.

## First steps using TFHE-rs JS on WASM API

### Setting up TFHE-rs JS on WASM API for Node.js programs

To build the JS on WASM bindings for **TFHE-rs**, install [`wasm-pack`](https://drager.github.io/wasm-pack/) and the necessary [`rust toolchain`](https://rustup.rs/). Clone the **TFHE-rs** repository and build using the following commands (this will build using the default branch, you can check out a specific tag depending on your requirements):

```shell
$ git clone https://github.com/zama-ai/tfhe-rs.git
Cloning into 'tfhe-rs'...
...
Resolving deltas: 100% (3866/3866), done.
$ cd tfhe-rs
$ cd tfhe
$ wasm-pack build --release --target=nodejs --features=boolean-js-wasm-api,integer-js-wasm-api,zk-pok,extended-types
[INFO]: Compiling to Wasm...
...
[INFO]: :-) Your wasm pkg is ready to publish at ...
```

The command above targets Node.js. To generate a binding for a web browser, use `--target=web`. However, this tutorial does not cover that particular use case.

The Boolean, shortint and integer features are enabled here, but it's possible to use them individually. To build the lighter client-only package instead, drop the default features and enable `integer-client-js-wasm-api` (optionally with `zk-pok`), as done by the `build_*_client` Makefile targets.

After the build, a new directory **pkg** is available in the `tfhe` directory.

```shell
$ ls pkg
LICENSE  README.md  package.json  tfhe.d.ts  tfhe.js  tfhe_bg.wasm  tfhe_bg.wasm.d.ts
$
```

### Commented code to generate keys for shortint and encrypt a ciphertext

{% hint style="info" %}
Make sure to update the path of the required clause in the example below to match the location of the TFHE package that was just built.
{% endhint %}

```javascript
// Here import assert to check the decryption went well and panic otherwise
const assert = require('node:assert').strict;
// Import the Shortint module from the TFHE-rs package generated earlier
const { Shortint, ShortintParametersName, ShortintParameters } = require("/path/to/built/tfhe/pkg");

function shortint_example() {
    // Get pre-defined parameters from the shortint module to manage messages with 4 bits of useful
    // information in total (2 bits of "message" and 2 bits of "carry")
    let params_name = ShortintParametersName.PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128;
    let params = new ShortintParameters(params_name);
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

Then, you can run the `example.js` script using [`node`](https://nodejs.org/) as follows:

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
