# Rust configuration

This document provides basic instructions to configure the Rust toolchain and features for **TFHE-rs.**

**TFHE-rs** requires a nightly Rust toolchain to build the C API and utilize advanced SIMD instructions. However, for other uses, a stable toolchain (version 1.81 or later) is sufficient.

Follow the following instructions to install the necessary Rust toolchain:

```shell
# If you don't need the C API or the advanced still unstable SIMD instructions use this
rustup toolchain install stable
# Otherwise install a nightly toolchain
rustup toolchain install nightly
```

## Setting the toolchain

You can set the toolchain using either of the following methods.

Manually specify the toolchain for each cargo command:

```shell
# By default the +stable should not be needed, but we add it here for completeness
cargo +stable build --release
cargo +stable test --release
# Or
cargo +nightly build --release
cargo +nightly test --release
```

Override the toolchain for the current project:

```shell
# This should not be necessary by default, but if you want to make sure your configuration is
# correct you can still set the overridden toolchain to stable
rustup override set stable
# cargo will use the `stable` toolchain.
cargo build --release
# Or
rustup override set nightly
# cargo will use the `nightly` toolchain.
cargo build --release
```

To verify the default toolchain used by Cargo, execute:

```shell
rustup show
```

## Choosing your features

**TFHE-rs** provides various cargo features to customize the types and features used.

### Homomorphic types

This crate provides 3 kinds of data types. Each kind is enabled by activating the corresponding feature in the TOML line and has multiple types:

| Kind      | Features   | Type (s)                 |
| --------- | ---------- | ------------------------ |
| Booleans  | `boolean`  | Booleans                 |
| ShortInts | `shortint` | Short integers           |
| Integers  | `integer`  | Arbitrary-sized integers |

### AVX-512

While the library generally selects automatically the best instruction sets available by the host, in the case of 'AVX-512', you have to choose it explicitly. This requires to use a [nightly toolchain](rust\_configuration.md#using-tfhe-rs-with-nightly-toolchain) with the feature `nightly-avx512`.

```shell
cargo +nightly build --release --features=nightly-avx512
```
