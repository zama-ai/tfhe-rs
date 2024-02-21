# Using the right toolchain for TFHE-rs.

TFHE-rs only requires a nightly toolchain for building the C API and using advanced SIMD instructions, otherwise you can use a stable toolchain (with version >= 1.72)
Install the needed Rust toolchain:

```shell
# If you don't need the C API or the advanced still unstable SIMD instructions use this
rustup toolchain install stable
# Otherwise install a nightly toolchain
rustup toolchain install nightly
```

Then, you can either:

* Manually specify the toolchain to use in each of the cargo commands:

```shell
# By default the +stable should not be needed, but we add it here for completeness
cargo +stable build
cargo +stable test
# Or
cargo +nightly build
cargo +nightly test
```

* Or override the toolchain to use for the current project:

```shell
# This should not be necessary by default, but if you want to make sure your configuration is
# correct you can still set the overridden toolchain to stable
rustup override set stable
# cargo will use the `stable` toolchain.
cargo build
# Or
rustup override set nightly
# cargo will use the `nightly` toolchain.
cargo build
```

To check the toolchain that Cargo will use by default, you can use the following command:

```shell
rustup show
```


# Choosing your features

`TFHE-rs` exposes different `cargo features` to customize the types and features used.

## Homomorphic Types.

This crate exposes two kinds of data types. Each kind is enabled by activating its corresponding feature in the TOML line. Each kind may have multiple types:

| Kind      | Features   | Type(s)                   |
|-----------|------------|---------------------------|
| Booleans  | `boolean`  | Booleans                  |
| ShortInts | `shortint` | Short integers            |
| Integers  | `integer`  | Arbitrary-sized  integers |


## AVX-512

In general, the library automatically chooses the best instruction sets available by the host. However, in the case of 'AVX-512', this has to be explicitly chosen as a feature. This requires to use a [nightly toolchain](#using-tfhe-rs-with-nightly-toolchain) along with the feature `nightly-avx512`.

```shell
cargo +nightly build --features=nightly-avx512
```
