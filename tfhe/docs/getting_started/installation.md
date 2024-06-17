# Installation

This document provides instructions to set up **TFHE-rs** in your project.

## Importing

First, add **TFHE-rs** as a dependency in your `Cargo.toml`.

**For `x86_64` machine running a Unix-like OS:**

```toml
tfhe = { version = "0.6.3", features = [ "boolean", "shortint", "integer", "x86_64-unix" ] }
```

**For `ARM` machine running a Unix-like OS:**

```toml
tfhe = { version = "0.6.3", features = [ "boolean", "shortint", "integer", "aarch64-unix" ] }
```

**For `x86_64` machines with the** [**`rdseed instruction`**](https://en.wikipedia.org/wiki/RDRAND) **running Windows:**

```toml
tfhe = { version = "*", features = ["boolean", "shortint", "integer", "x86_64"] }
```

{% hint style="info" %}
**Rust version**: a minimum Rust version of 1.73 is required to compile **TFHE-rs**.
{% endhint %}

{% hint style="success" %}
**Performance**: for optimal performance, it is highly recommended to run code that uses **`TFHE-rs`** in release mode with cargo's `--release` flag.
{% endhint %}

## Supported platforms

**TFHE-rs** currently supports the following platforms:

| OS      | x86                                | aarch64          |
| ------- | ---------------------------------- | ---------------- |
| Linux   | `x86_64-unix`                      | `aarch64-unix`\* |
| macOS   | `x86_64-unix`                      | `aarch64-unix`\* |
| Windows | `x86_64` with `RDSEED` instruction | Unsupported      |
