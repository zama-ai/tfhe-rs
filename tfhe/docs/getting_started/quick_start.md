# Quick Start

This library makes it possible to execute **homomorphic operations over encrypted data**, where the data are either Booleans or short integers (named shortint in the rest of this documentation). It allows one to execute a circuit on an **untrusted server** because both circuit inputs and outputs are kept **private**. Data are indeed encrypted on the client side, before being sent to the server. On the server side, every computation is performed on ciphertexts.

The server, however, has to know the circuit to be evaluated. At the end of the computation, the server returns the encryption of the result to the user. She can then decrypt it with her `secret key`.

## General method to write an homomorphic circuit program

The overall process to write an homomorphic program is the same for both Boolean and shortint types. In a nutshell, the basic steps for using the TFHE-rs library are the following:

* Choose a data type (Boolean or shortint)
* Import the library
* Create client and server keys
* Encrypt data with the client key
* Compute over encrypted data using the server key
* Decrypt data with the client key


### API Levels

This library has different modules, with different level of abstraction.

There is a the core_crypto module which is the lowest level API, with the primitive
functions and types of the TFHE scheme.

The are the boolean, shortint and integer modules which are based on the core_crypto,
to allow construction of respectively, booleans, short integers, and integers circuits.

Then there is the high-level module built on top of the boolean, shortint, integer modules,
this module is meant to abstract as much as possible the TFHE part and allow quick development of
FHE applications.

#### High Level API

tfhe-rs by default exposes a High Level API, that manages the server_key and proposes datatypes
that try to match Rust's native types by having overloaded operators (+, -, ...).

Here is an example to illustrate how the high level API is used.

{% hint style="info" %}
Use the `--release` flag to run this example (eg: `cargo run --release`)
{% endhint %}


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

#### Boolean example.

Here is an example to illustrate how the library can be used to evaluate a Boolean circuit:

{% hint style="info" %}
Use the `--release` flag to run this example (eg: `cargo run --release`)
{% endhint %}

```rust
use tfhe::boolean::prelude::*;

fn main() {
    // We generate a set of client/server keys, using the default parameters:
    let (client_key, server_key) = gen_keys();

    // We use the client secret key to encrypt two messages:
    let ct_1 = client_key.encrypt(true);
    let ct_2 = client_key.encrypt(false);

    // We use the server public key to execute a boolean circuit:
    // if ((NOT ct_2) NAND (ct_1 AND ct_2)) then (NOT ct_2) else (ct_1 AND ct_2)
    let ct_3 = server_key.not(&ct_2);
    let ct_4 = server_key.and(&ct_1, &ct_2);
    let ct_5 = server_key.nand(&ct_3, &ct_4);
    let ct_6 = server_key.mux(&ct_5, &ct_3, &ct_4);

    // We use the client key to decrypt the output of the circuit:
    let output = client_key.decrypt(&ct_6);
    assert_eq!(output, true);
}
```

#### Shortint example.

And here is a full example using shortint:

{% hint style="info" %}
Use the `--release` flag to run this example (eg: `cargo run --release`)
{% endhint %}

```rust
use tfhe::shortint::prelude::*;

fn main() {
    // We generate a set of client/server keys, using the default parameters:
    let (client_key, server_key) = gen_keys(Parameters::default());

    let msg1 = 1;
    let msg2 = 0;

    let modulus = client_key.parameters.message_modulus.0;

    // We use the client key to encrypt two messages:
    let ct_1 = client_key.encrypt(msg1);
    let ct_2 = client_key.encrypt(msg2);

    // We use the server public key to execute an integer circuit:
    let ct_3 = server_key.unchecked_add(&ct_1, &ct_2);

    // We use the client key to decrypt the output of the circuit:
    let output = client_key.decrypt(&ct_3);
    assert_eq!(output, (msg1 + msg2) % modulus as u64);
}
```

#### Integer example.

{% hint style="info" %}
Use the `--release` flag to run this example (eg: `cargo run --release`)
{% endhint %}

```rust
use tfhe::integer::gen_keys_radix;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;

fn main() {
    // We create keys for radix represention to create 16 bits integers
    // using 8 blocks of 2 bits
    let (cks, sks) = gen_keys_radix(&PARAM_MESSAGE_2_CARRY_2, 8);

    let clear_a = 2382u16;
    let clear_b = 29374u16;

    let mut a = cks.encrypt(clear_a as u64);
    let mut b = cks.encrypt(clear_b as u64);

    let encrypted_max = sks.smart_max_parallelized(&mut a, &mut b);
    let decrypted_max: u64 = cks.decrypt(&encrypted_max);

    assert_eq!(decrypted_max as u16, clear_a.max(clear_b))
}
```

The library is pretty simple to use, and can evaluate **homomorphic circuits of arbitrary length**. The description of the algorithms can be found in the [TFHE](https://doi.org/10.1007/s00145-019-09319-x) paper (also available as [ePrint 2018/421](https://ia.cr/2018/421)).
