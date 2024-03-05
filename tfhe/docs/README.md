# Welcome to TFHE-rs

⭐️ [Star the repo on Github](https://github.com/zama-ai/tfhe-rs)  | 💬 [Community support](https://community.zama.ai/) | 📚 [FHE resources by Zama](https://github.com/zama-ai/awesome-zama/tree/main)

<figure><picture><source srcset=".gitbook/assets/doc header.png" media="(prefers-color-scheme: dark)"><img src=".gitbook/assets/doc header.png" alt=""></picture><figcaption></figcaption></figure>

**TFHE-rs** is a pure Rust implementation of TFHE for Boolean and integer arithmetics over encrypted data. It includes a Rust and C API, as well as a client-side WASM API.

### Get started

Learn the basics of TFHE-rs, set it up, and make it run with ease.

<table data-card-size="large" data-view="cards"><thead><tr><th align="center"></th><th data-hidden data-card-target data-type="content-ref"></th></tr></thead><tbody><tr><td align="center">What is TFHE-rs?</td><td><a href="broken-reference">Broken link</a></td></tr><tr><td align="center">Installation</td><td><a href="getting_started/installation.md">installation.md</a></td></tr><tr><td align="center">Quick start</td><td><a href="getting_started/quick_start.md">quick_start.md</a></td></tr><tr><td align="center">Benchmarks</td><td><a href="getting_started/benchmarks.md">benchmarks.md</a></td></tr></tbody></table>

### Build with TFHE-rs

Start building with TFHE-rs by exploring its core features, discovering essential guides, and learning more with user-friendly tutorials.

<table data-view="cards"><thead><tr><th align="center"></th><th></th><th></th><th data-hidden data-card-cover data-type="files"></th></tr></thead><tbody><tr><td align="center"><strong>Fundamentals</strong></td><td>Explore the core features  and basics of TFHE-rs.</td><td><ul><li><a href="fundamentals/configure-and-create-keys.md">Configure and create keys</a></li><li><a href="fundamentals/set-the-server-key.md">Set the server key</a></li><li><a href="fundamentals/encrypt-data.md">Encrypt data</a></li><li><a href="fundamentals/compute-and-decrypt.md">Compute and decrypt</a></li></ul></td><td><a href=".gitbook/assets/fundamentals.png">fundamentals.png</a></td></tr><tr><td align="center"><strong>Guides</strong></td><td>Discover essential guides to work with TFHE-rs.</td><td><ul><li><a href="guides/run_on_gpu.md">Run on GPU</a></li><li><a href="guides/rust_configuration.md">Configure Rust</a></li><li><a href="guides/overflow_operations.md">Detect overflow</a></li><li><a href="guides/c_api.md">Use the C API</a></li></ul></td><td><a href=".gitbook/assets/guides.png">guides.png</a></td></tr><tr><td align="center"><strong>Tutorials</strong></td><td>Learn more about TFHE-rs with our tutorials.</td><td><ul><li><a href="tutorials/see-all-tutorials.md#start-here">Start here</a></li><li><a href="tutorials/see-all-tutorials.md#go-further">Go further</a></li><li><a href="tutorials/see-all-tutorials.md">See all tutorials</a></li></ul></td><td><a href=".gitbook/assets/tutorials.png">tutorials.png</a></td></tr></tbody></table>

### References & Explanations

Take a deep dive into TFHE-rs, exploring APIs from the highest to the lowest level of abstraction and accessing additional resources for in-depth explanations&#x20;

<table data-card-size="large" data-view="cards"><thead><tr><th align="center"></th><th align="center"></th><th data-hidden data-card-target data-type="content-ref"></th></tr></thead><tbody><tr><td align="center"><strong>API references</strong></td><td align="center">High-level API that abstracts cryptographic complexities and simplifies the development</td><td><a href="https://docs.rs/tfhe/latest/tfhe/">https://docs.rs/tfhe/latest/tfhe/</a></td></tr><tr><td align="center"><strong>Fine-grained APIs</strong></td><td align="center">Mid-level API that enables evaluation of Boolean, short integer, and integer circuits</td><td><a href="references/fine-grained-apis/">fine-grained-apis</a></td></tr><tr><td align="center"><strong>Crypto core API</strong></td><td align="center">Low-level API with the primitive functions and types of the TFHE scheme</td><td><a href="references/crypto-core-api/">crypto-core-api</a></td></tr><tr><td align="center"><strong>TFHE deep dive</strong></td><td align="center">Resources that explain the Fully Homomorphic Encryption scheme - TFHE</td><td><a href="explanations/tfhe-deep-dive.md">tfhe-deep-dive.md</a></td></tr></tbody></table>

### Supports

Our team of experts usually answers within 24 hours in working days.

<table data-card-size="large" data-view="cards"><thead><tr><th align="center"></th><th align="center"></th><th data-hidden data-card-target data-type="content-ref"></th></tr></thead><tbody><tr><td align="center">💬 <strong>Community Forum</strong></td><td align="center">Ask technical questions to the Zama team and find solutions to common issues</td><td><a href="https://community.zama.ai/">https://community.zama.ai/</a></td></tr><tr><td align="center">👾 <strong>Discord Channel</strong></td><td align="center">Discuss FHE-related topics with the FHE community in real-time</td><td><a href="https://discord.com/invite/fhe-org">https://discord.com/invite/fhe-org</a></td></tr></tbody></table>

### Developers

* [Contribute to TFHE-rs](dev/contributing.md)
* [Check the latest release note](https://github.com/zama-ai/tfhe-rs/releases)
* [Request a feature ](https://github.com/zama-ai/tfhe-rs/issues/new?assignees=\&labels=feature\_request\&projects=\&template=feature\_request.md\&title=)
* [Report a bug](https://github.com/zama-ai/tfhe-rs/issues/new?assignees=\&labels=triage\_required\&projects=\&template=bug\_report.md\&title=)
