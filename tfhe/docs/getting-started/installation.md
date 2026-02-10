# Installation

This document provides instructions to set up **TFHE-rs** in your project.

## Importing

First, add **TFHE-rs** as a dependency in your `Cargo.toml`.

```toml
tfhe = { version = "~1.5.3", features = ["boolean", "shortint", "integer"] }
```

{% hint style="info" %}
**Rust version**: a minimum Rust version of 1.84 is required to compile **TFHE-rs**.
{% endhint %}

{% hint style="success" %}
**Performance**: for optimal performance, it is highly recommended to run code that uses **`TFHE-rs`** in release mode with cargo's `--release` flag.
{% endhint %}

## Supported platforms

**TFHE-rs** currently supports the following platforms:

| OS      | x86_64                              | aarch64     |
|---------|-------------------------------------|-------------|
| Linux   | Supported                           | Supported\* |
| macOS   | Supported                           | Supported\* |
| Windows | Supported with `RDSEED` instruction | Unsupported |

By default, **TFHE-rs** makes the assumption that hardware AES features are enabled on the target CPU. The required CPU features are:
- x86_64: sse2, aesni
- aarch64: aes, neon

To add support for older CPU, import **TFHE-rs** with the `software-prng` feature in your `Cargo.toml`:

```toml
tfhe = { version = "~1.5.3", features = ["boolean", "shortint", "integer", "software-prng"] }
```

## Hardware acceleration

**TFHE-rs** now features hardware-accelerated backends.

You can refer to the:
- [GPU backend instructions](../configuration/gpu-acceleration/run-on-gpu.md) to benefit from GPU accelerated primitives.
- [HPU backend instructions](../configuration/hpu-acceleration/run-on-hpu.md) to benefit from custom FPGA accelerated primitives.
