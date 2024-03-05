---
description: >-
  TFHE-rs is a pure Rust implementation of TFHE for Boolean and integer
  arithmetics over encrypted data. It includes a Rust and C API, as well as a
  client-side WASM API.
layout:
  title:
    visible: true
  description:
    visible: true
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: false
---

# Welcome to TFHE-rs

## Get started

Learn the basics of TFHE-rs, set it up, and make it run with ease.

<table data-view="cards"><thead><tr><th></th><th data-hidden data-card-target data-type="content-ref"></th><th data-hidden data-card-cover data-type="files"></th></tr></thead><tbody><tr><td><strong>What is TFHE-rs?</strong></td><td><a href="getting_started/">getting_started</a></td><td><a href=".gitbook/assets/yellow1.png">yellow1.png</a></td></tr><tr><td><strong>Installation</strong></td><td><a href="getting_started/installation.md">installation.md</a></td><td><a href=".gitbook/assets/yellow2.png">yellow2.png</a></td></tr><tr><td><strong>Quick start</strong></td><td><a href="getting_started/quick_start.md">quick_start.md</a></td><td><a href=".gitbook/assets/yellow3.png">yellow3.png</a></td></tr></tbody></table>

## Build with TFHE-rs

Start building with TFHE-rs by exploring its core features, discovering essential guides, and learning more with user-friendly tutorials.

<table data-view="cards"><thead><tr><th></th><th></th><th></th><th data-hidden data-card-cover data-type="files"></th></tr></thead><tbody><tr><td><strong>Fundamentals</strong></td><td>Explore the core features and basics of TFHE-rs.<br><br></td><td><ul><li><a href="fundamentals/configure-and-generate-keys.md">Configure and generate keys</a></li><li><a href="fundamentals/set-the-server-key.md">Set the server key</a></li><li><a href="fundamentals/encrypt-data.md">Encrypt data</a></li><li><a href="fundamentals/compute.md">Compute on encrypted data</a></li><li><a href="fundamentals/decrypt-data.md">Decrypt data</a></li></ul></td><td><a href=".gitbook/assets/orange1.png">orange1.png</a></td></tr><tr><td><strong>Guides</strong></td><td>Discover essential guides to work with TFHE-rs.<br><br></td><td><ul><li><a href="guides/run_on_gpu.md">Run on GPU</a></li><li><a href="guides/rust_configuration.md">Configure Rust</a></li><li><a href="guides/overflow_operations.md">Detect overflow</a></li><li><a href="guides/c_api.md">Use the C API</a></li></ul></td><td><a href=".gitbook/assets/orange2.png">orange2.png</a></td></tr><tr><td><strong>Tutorials</strong></td><td>Learn more about TFHE-rs with our tutorials.<br><br></td><td><ul><li><a href="tutorials/see-all-tutorials.md#start-here">Start here</a></li><li><a href="tutorials/see-all-tutorials.md#go-further">Go further</a></li><li><a href="tutorials/see-all-tutorials.md">See all tutorials</a></li></ul></td><td><a href=".gitbook/assets/orange3.png">orange3.png</a></td></tr></tbody></table>

## Explore more

Access to additional resources and join the Zama community.

### References & Explanations

Take a deep dive into TFHE-rs, exploring APIs from the highest to the lowest level of abstraction and accessing additional resources for in-depth explanations.

* [Rust API reference](https://docs.rs/tfhe/latest/tfhe/): High-level API that abstracts cryptographic complexities and simplifies the development and more
* [Fine-grained APIs](references/fine-grained-apis/): Mid-level APIs that enable evaluation of Boolean, short integer, and integer circuits
* [Core crypto API](references/core-crypto-api/): Low-level API with the primitive functions and types of the TFHE scheme
* [TFHE deep dive](explanations/tfhe-deep-dive.md): Resources that explain the Fully Homomorphic Encryption scheme - TFHE

### Support channels

Ask technical questions and discuss with the community. Our team of experts usually answers within 24 hours during working days.

* [Community forum](https://community.zama.ai/)
* [Discord channel](https://discord.com/invite/fhe-org)

### Developers

Collaborate with us to advance the FHE spaces and drive innovation together.

* [Contribute to TFHE-rs](dev/contributing.md)
* [Check the latest release note](https://github.com/zama-ai/tfhe-rs/releases)
* [Request a feature](https://github.com/zama-ai/tfhe-rs/issues/new?assignees=\&labels=feature\_request\&projects=\&template=feature\_request.md\&title=)
* [Report a bug](https://github.com/zama-ai/tfhe-rs/issues/new?assignees=\&labels=triage\_required\&projects=\&template=bug\_report.md\&title=)

***

We value your feedback! [Take a 5-question developer survey](https://www.zama.ai/developer-survey) to improve the TFHE-rs library and the documentation and help other developers use FHE.
