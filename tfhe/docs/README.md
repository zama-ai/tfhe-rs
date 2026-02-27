---
description:
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

TFHE-rs is a pure Rust implementation of TFHE for Boolean and integer arithmetics over encrypted data. It includes a Rust and C API, as well as a client-side WASM API.

TFHE-rs also includes a [GPU accelerated backend](configuration/gpu-acceleration/run-on-gpu.md) as well as an [HPU accelerated backend](configuration/hpu-acceleration/run-on-hpu.md).

## Get started

Learn the basics of TFHE-rs, set it up, and make it run with ease.

<table data-view="cards"><thead><tr><th></th><th></th><th data-hidden data-card-target data-type="content-ref"></th><th data-hidden data-card-cover data-type="files"></th></tr></thead><tbody><tr><td><strong>What is TFHE-rs?</strong></td><td>Understand TFHE-rs library and basic cryptographic concepts</td><td><a href="getting-started/README.md">getting-started</a></td><td><a href=".gitbook/assets/yellow-gradient.png">yellow-gradient.png</a></td></tr><tr><td><strong>Installation</strong></td><td>Follow the step by step guide to import TFHE-rs in your project</td><td><a href="getting-started/installation.md">installation.md</a></td><td><a href=".gitbook/assets/orange-gradient.png">orange-gradient.png</a></td></tr><tr><td><strong>Quick start</strong></td><td>See a full example of using TFHE-rs to compute on encrypted data</td><td><a href="getting-started/quick-start.md">quick-start.md</a></td><td><a href=".gitbook/assets/grey-gradient.png">grey-gradient.png</a></td></tr></tbody></table>

## Build with TFHE-rs

Start building with TFHE-rs by exploring its core features, discovering essential guides, and learning more with user-friendly tutorials.

<table data-view="cards"><thead><tr><th></th><th></th><th></th><th data-hidden data-card-cover data-type="files"></th></tr></thead><tbody><tr><td><strong>FHE Computations</strong></td><td>Run FHE computation on encrypted data.</td><td><ul><li><a href="fhe-computation/types/">Types </a></li><li><a href="fhe-computation/operations/">Operations</a></li></ul></td><td><a href=".gitbook/assets/bronze-gradient.png">bronze-gradient.png</a></td></tr><tr><td><strong>Configuration</strong></td><td>Advanced configuration for better performance.</td><td><ul><li><a href="configuration/rust-configuration.md">Advanced Rust </a></li><li><a href="configuration/gpu-acceleration/run-on-gpu.md">GPU acceleration</a></li><li><a href="configuration/hpu-acceleration/run-on-hpu.md">HPU acceleration</a></li></ul></td><td><a href=".gitbook/assets/yellow-gradient.png">yellow-gradient.png</a></td></tr><tr><td><strong>Integration</strong></td><td>Use TFHE-rs in different contexts or platforms..</td><td><ul><li><a href="integration/c-api.md">C API</a></li><li><a href="integration/js-on-wasm-api.md">JS on WASM API</a></li></ul></td><td><a href=".gitbook/assets/orange-gradient.png">orange-gradient.png</a></td></tr></tbody></table>

## Explore more

Access to additional resources and join the Zama community.

### Tutorials

Explore step-by-step guides that walk you through real-world uses of TFHE-rs.&#x20;

* [Homomorphic parity bit](tutorials/parity-bit.md): Learn how to implement a parity bit calculation over encrypted data
* [Homomorphic case changing on ASCII string](tutorials/ascii-fhe-string.md): See how to process string data securely by changing cases while keeping the data encrypted.
* [SHA256 with Boolean API](tutorials/sha256-bool.md): Delve into a more complex example: implementing the SHA256 hash function entirely on encrypted boolean values.
* [All tutorials](tutorials/see-all-tutorials.md): A complete list of all available tutorials in one place.tutorials: A complete list of all available tutorials in one place.

### References & Explanations

Take a deep dive into TFHE-rs, exploring APIs from the highest to the lowest level of abstraction and accessing additional resources for in-depth explanations.

* [Rust API reference](https://docs.rs/tfhe/latest/tfhe/): High-level API that abstracts cryptographic complexities and simplifies the development and more
* [Fine-grained APIs](references/fine-grained-apis/): Mid-level APIs that enable evaluation of Boolean, short integer, and integer circuits
* [Core crypto API](references/core-crypto-api/): Low-level API with the primitive functions and types of the TFHE scheme
* [TFHE deep dive](explanations/tfhe-deep-dive.md): Resources that explain the Fully Homomorphic Encryption scheme - TFHE
* [TFHE-rs handbook](https://github.com/zama-ai/tfhe-rs-handbook): Document describing algorithms implemented in TFHE-rs

### Support channels

Ask technical questions and discuss with the community. Our team of experts usually answers within 24 hours during working days.

* [Community forum](https://community.zama.org/)
* [Discord channel](https://discord.com/invite/fhe-org)

### Developers

Collaborate with us to advance the FHE spaces and drive innovation together.

* [Contribute to TFHE-rs](../../CONTRIBUTING.md)
* [Check the latest release note](https://github.com/zama-ai/tfhe-rs/releases)
* [Request a feature](https://github.com/zama-ai/tfhe-rs/issues/new?assignees=\&labels=feature_request\&projects=\&template=feature_request.md\&title=)
* [Report a bug](https://github.com/zama-ai/tfhe-rs/issues/new?assignees=\&labels=triage_required\&projects=\&template=bug_report.md\&title=)

***
