# Installation

## Importing into your project

To use `TFHE-rs` in your project, you first need to add it as a dependency in your `Cargo.toml`:

```toml
tfhe = { version = "0.2.3", features = [ "boolean", "shortint", "integer", "x86_64-unix" ] }
```

{% hint style="info" %}
When running code that uses `tfhe-rs`, it is highly recommended to run in release mode with cargo's `--release` flag to have the best performances possible, eg: `cargo run --release`.
{% endhint %}

## Choosing your features

`TFHE-rs` exposes different `cargo features` to customize the types and features used.

### Kinds.

This crate exposes two kinds of data types. Each kind is enabled by activating its corresponding feature in the TOML line. Each kind may have multiple types:

| Kind      | Features   | Type(s)                           |
| --------- | ---------- | --------------------------------- |
| Booleans  | `boolean`  | Booleans                          |
| ShortInts | `shortint` | Short unsigned integers           |
| Integers  | `integer`  | Arbitrary-sized unsigned integers |

### Serialization.

The different data types and keys exposed by the crate can be serialized / deserialized.

More information can be found [here](../Boolean/serialization.md) for Boolean and [here](../shortint/serialization.md) for shortint.

## Supported platforms

TFHE-rs is supported on Linux (x86, aarch64), macOS (x86, aarch64) and Windows (x86 with `RDSEED` instruction).

| OS      | x86           | aarch64          |
| ------- | ------------- | ---------------- |
| Linux   | `x86_64-unix` | `aarch64-unix`\* |
| macOS   | `x86_64-unix` | `aarch64-unix`\* |
| Windows | `x86_64`      | Unsupported      |

{% hint style="info" %}
Users who have ARM devices can use `TFHE-rs` by compiling using the `nightly` toolchain.
{% endhint %}

### Using TFHE-rs with nightly toolchain.

Install the needed Rust toolchain:

```shell
rustup toolchain install nightly
```

Then, you can either:

* Manually specify the toolchain to use in each of the cargo commands:

```shell
cargo +nightly build
cargo +nightly test
```

* Or override the toolchain to use for the current project:

```shell
rustup override set nightly
# cargo will use the `nightly` toolchain.
cargo build
```

To check the toolchain that Cargo will use by default, you can use the following command:

```shell
rustup show
```
