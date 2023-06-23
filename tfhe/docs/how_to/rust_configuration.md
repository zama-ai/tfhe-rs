# Using TFHE-rs with nightly toolchain.

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


# Choosing your features

`TFHE-rs` exposes different `cargo features` to customize the types and features used.

## Homomorphic Types.

This crate exposes two kinds of data types. Each kind is enabled by activating its corresponding feature in the TOML line. Each kind may have multiple types:

| Kind      | Features   | Type(s)                           |
| --------- | ---------- | --------------------------------- |
| Booleans  | `boolean`  | Booleans                          |
| ShortInts | `shortint` | Short unsigned integers           |
| Integers  | `integer`  | Arbitrary-sized unsigned integers |


## AVX-512

In general, the library automatically chooses the best instruction sets available by the host. However, in the case of 'AVX-512', this has to explicitly chosen as a feature. This requires to use the [nightly toolchain](#using-tfhe-rs-with-nightly-toolchain) along with the feature `nightly-avx512`.

```shell
cargo +nightly build --features=nightly-avx512
```
