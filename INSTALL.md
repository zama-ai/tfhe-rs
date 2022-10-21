# Installation

The Rust compiler can be installed on __Linux__ and __macOS__ with the following command:

```bash
curl  --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

On __Windows__ you need to download the correct `rustup-init.exe` binary and run it, see [the rust documentation on that topic](https://forge.rust-lang.org/infra/other-installation-methods.html#other-ways-to-install-rustup).

Other rust installation methods are available on the
[rust website](https://forge.rust-lang.org/infra/other-installation-methods.html).

## Apple Silicon

Building the project on Apple Silicon without an efficient CSPRNG is possible using the default stable rust toolchain.

To use the efficient CSPRNG, building the crate requires a nightly toolchain.

```shell
rustup install nightly
```

You then can override the toolchain for your local repository using:
```shell
rustup override set nightly
```

## Windows

Can be built, indicate how (no default features, no unix seeder), requires a hardware seeder x86_64
