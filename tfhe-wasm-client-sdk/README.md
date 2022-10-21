# WASM client SDK

This crate exposes a WASM interface for the so called "client-side" APIs of the project. Using these APIs, it is possible to run operations such as key generation, encryption and decryption.

## Building the client wasm SDK

To build the client wasm SDK, you will need a `rust` toolchain as well as `wasm-pack`. This tool will call the rust compiler to generate the `wasm` code and generate a javascript file containing boilerplate to ease the integration for your usecase (be it `nodejs`, or for the browser).

To install `wasm-pack` see [the project homepage](https://rustwasm.github.io/wasm-pack/installer/).

You can use `wasm-pack` to compile the client wasm SDK with the following command:
```shell
# For use with nodejs
wasm-pack build --release --target=nodejs
# For use with a Bundler-like web pack
wasm-pack build --release --target=bundler
# For use in the browser
wasm-pack build --release --target=web
```

## License

This software is distributed under the BSD-3-Clause-Clear license. If you have any questions,
please contact us at `hello@zama.ai`.
