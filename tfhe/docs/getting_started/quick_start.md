# Quick start

This document explains the basic steps of using the high-level API of **TFHE-rs.**

## Setting up a Rust project

If you already know how to set up a Rust project, feel free to go directly to the next [section](#using-tfhe-rs-and-its-apis).

First, install the Rust programming language tools. Visit https://rustup.rs/ and follow the instructions. For alternative installation methods, refer to the [official Rust installation page](https://rust-lang.github.io/rustup/installation/other.html).

After installing Rust, you can call the build and package manager `Cargo`:

```console
$ cargo --version
cargo 1.81.0 (2dbb1af80 2024-08-20)
```

Your version may differ depending on when you installed Rust. To update your installation, invoke `rustup update`.

Now you can invoke `Cargo` and create a new default Rust project:

```console
$ cargo new tfhe-example
    Creating binary (application) `tfhe-example` package
note: see more `Cargo.toml` keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html
```

This will create a `tfhe-example` directory and populate it with the following:

```console
$ tree tfhe-example/
tfhe-example/
├── Cargo.toml
└── src
    └── main.rs

1 directory, 2 files
```

You now have a minimal Rust project.

In the next section, we'll explain how to add **TFHE-rs** as a dependency to the project and start using it to perform FHE computations.

## Using TFHE-rs and its APIs

To use **TFHE-rs**, you need to add it as a dependency to `tfhe-example`.

The `Cargo.toml` file is located at the root of the project. Initially, the file is minimal and doesn't contain any dependencies:

```toml
[package]
name = "tfhe-example"
version = "0.1.0"
edition = "2021"

[dependencies]
```

For x86 Unix systems, add the following configuration to include **TFHE-rs**:

```toml
tfhe = { version = "0.10.0", features = ["integer", "x86_64-unix"] }
```

Your updated `Cargo.toml` file should look like this:

```toml
[package]
name = "tfhe-example"
version = "0.1.0"
edition = "2021"

[dependencies]
tfhe = { version = "0.10.0", features = ["integer", "x86_64-unix"] }
```

If you are on a different platform please refer to the [installation documentation](installation.md) for configuration options of other supported platforms.

Now that the project has **TFHE-rs** as a dependency here are the detailed steps to use its high-level API:

1. Import the **TFHE-rs** prelude with the following Rust code: `use tfhe::prelude::*;`
2. Client-side: [configure and generate keys](../fundamentals/configure-and-generate-keys.md)
3. Client-side: [encrypt data](../fundamentals/encrypt-data.md)
4. Server-side: [set the server key](../fundamentals/set-the-server-key.md)
5. Server-side: [compute over encrypted data](../fundamentals/compute.md)
6. Client-side: [decrypt data](../fundamentals/decrypt-data.md)

This example demonstrates the basic workflow combining the client and server parts:

```rust
use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint8};
use tfhe::prelude::*;

fn main() {
    let config = ConfigBuilder::default().build();

    // Client-side
    let (client_key, server_key) = generate_keys(config);

    let clear_a = 27u8;
    let clear_b = 128u8;

    let a = FheUint8::encrypt(clear_a, &client_key);
    let b = FheUint8::encrypt(clear_b, &client_key);

    //Server-side
    set_server_key(server_key);
    let result = a + b;

    //Client-side
    let decrypted_result: u8 = result.decrypt(&client_key);

    let clear_result = clear_a + clear_b;

    assert_eq!(decrypted_result, clear_result);
}
```

You can learn more about homomorphic types and associated compilation features in the [configuration documentation.](../guides/rust\_configuration.md)
