# Quick Start

The basic steps for using the high level API of tfhe are the following:

- importing tfhe
- configuring and creating keys
- setting server key
- encrypting data
- computing over encrypted data
- decrypting data

Here is the full example that we will walk through:

```rust
use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint8};
use tfhe::prelude::*;

fn main() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_uint8()
        .build();

    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    let clear_a = 27u8;
    let clear_b = 128u8;

    let a = FheUint8::encrypt(clear_a, &client_key);
    let b = FheUint8::encrypt(clear_b, &client_key);

    let result = a + b;

    let decrypted_result: u8 = result.decrypt(&client_key);

    let clear_result = clear_a + clear_b;

    assert_eq!(decrypted_result, clear_result);
}
```

```toml
tfhe = { version = "0.2.0", features = ["integer"]}
```

## Imports

`tfhe` uses `traits` to have a consistent API for creating FHE types and enable users to write generic functions. However, to be able to use associated functions and methods of a trait, the trait has to be in scope.

To make it easier for users, we use the `prelude` 'pattern'. That is, all `tfhe` important traits are in a `prelude` module that you **glob import**. With this, there is no need to remember or know the traits to import.

```rust
use tfhe::prelude::*;
```

## 1. Configuring and creating keys

The first step in your Rust code building is the creation of the configuration.

The configuration is used to declare which type you will use or not use, as well as enabling you
to use custom crypto-parameters for these types for more advanced usage / testing.

Creating a configuration is done using the ConfigBuilder type.

In our example, we are interested in using 8-bit unsigned integers with default parameters. As per the table on the Getting Started page, we need to enable the `integers` feature.

{% hint style="info" %}
```toml
tfhe = { version = "0.2.0", features = ["integer"]}
```
{% endhint %}

Next in our code, we create a config by first creating a builder with all types deactivated. Then, we enable the `uint8` type with default parameters.

```rust
use tfhe::{ConfigBuilder, generate_keys};

fn main() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_uint8()
        .build();

    let (client_key, server_key) = generate_keys(config);
}
```

The `generate_keys` command returns a client key and a server key.

As the names try to convey, the `client_key` is meant to stay private and not leave the client whereas the `server_key` can be made public and sent to a server for it to enable FHE computations.

## 2. Setting the server key

The next step is to call set_server_key

This function will **move** the server key to an internal state of the crate, allowing us to manage the details and give you, the user, a simpler interface.

```rust
use tfhe::{ConfigBuilder, generate_keys, set_server_key};

fn main() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_uint8()
        .build();

    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);
}
```

## 3. Encrypting Data

Encrypting data is done via the `encrypt` associated function of the [FheEncrypt] trait.

Types exposed by this crate will implement at least one of [FheEncrypt] or [FheTryEncrypt],
to allow enryption.

```Rust
let clear_a = 27u8;
let clear_b = 128u8;

let a = FheUint8::encrypt(clear_a, &client_key);
let b = FheUint8::encrypt(clear_b, &client_key);
```


## 4. Computation & decryption

Computations should be as easy as normal Rust to write, thanks to operator overloading.

```Rust
let result = a + b;
```

The decryption is done by using the `decrypt` method. (This method comes from the [FheDecrypt]
trait).

```Rust
let decrypted_result: u8 = result.decrypt(&client_key);

let clear_result = clear_a + clear_b;

assert_eq!(decrypted_result, clear_result);
```
