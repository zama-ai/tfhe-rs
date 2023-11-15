# Installation

## Cargo.toml

To use `concrete-integer`, you will need to add it to the list of dependencies
of your project, by updating your `Cargo.toml` file.

```toml
concrete-integer = "0.1.0"
```

### Supported platforms


As `concrete-integer` relies on `concrete-shortint`, which in turn relies on `concrete-core`,
the support ted platforms supported are:
 - `x86_64 Linux`
 - `x86_64 macOS`.

Windows users can use `concrete-integer` through the `WSL`.

macOS users which have the newer M1 (`arm64`) devices can use `concrete-integer` by cross-compiling to
`x86_64` and run their program with Rosetta.

First install the needed Rust toolchain:

```console
# Install the macOS x86_64 toolchain (you only need to do this once)
rustup toolchain install --force-non-host stable-x86_64-apple-darwin
```

Then you can either:

- Manually specify the toolchain to use in each of the cargo commands:

For example:

```console
cargo +stable-x86_64-apple-darwin build
cargo +stable-x86_64-apple-darwin test
```

- Or override the toolchain to use for the current project:

```console
rustup override set stable-x86_64-apple-darwin
# cargo will use the `stable-x86_64-apple-darwin` toolchain.
cargo build
```