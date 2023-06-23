# Quick Start

This library makes it possible to execute **homomorphic operations over encrypted data**, where the data are either Booleans, short integers (named shortint in the rest of this documentation), or integers up to 256 bits. It allows you to execute a circuit on an **untrusted server** because both circuit inputs and outputs are kept **private**. Data are indeed encrypted on the client side, before being sent to the server. On the server side, every computation is performed on ciphertexts.

The server, however, has to know the circuit to be evaluated. At the end of the computation, the server returns the encryption of the result to the user. Then the user can decrypt it with the `secret key`.

## General method to write an homomorphic circuit program

The overall process to write an homomorphic program is the same for all types. The basic steps for using the TFHE-rs library are the following:

1. Choose a data type (Boolean, shortint, integer)
2. Import the library
3. Create client and server keys
4. Encrypt data with the client key
5. Compute over encrypted data using the server key
6. Decrypt data with the client key

### API levels.

This library has different modules, with different levels of abstraction.

There is the **core\_crypto** module, which is the lowest level API with the primitive functions and types of the TFHE scheme.

Above the core\_crypto module, there are the **Boolean**, **shortint**, and **integer** modules, which contain easy to use APIs enabling evaluation of Boolean, short integer, and integer circuits.

Finally, there is the high-level module built on top of the Boolean, shortint, integer modules. This module is meant to abstract cryptographic complexities: no cryptographical knowledge is required to start developing an FHE application. Another benefit of the high-level module is the drastically simplified development process compared to lower level modules.

#### high-level API

TFHE-rs exposes a high-level API by default that includes datatypes that try to match Rust's native types by having overloaded operators (+, -, ...).

Here is an example of how the high-level API is used:

{% hint style="warning" %}
Use the `--release` flag to run this example (eg: `cargo run --release`)
{% endhint %}

```rust
use tfhe::{ConfigBuilder, generate_keys, set_server_key, FheUint8};
use tfhe::prelude::*;

fn main() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
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

#### Boolean example

Here is an example of how the library can be used to evaluate a Boolean circuit:

{% hint style="warning" %}
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

#### shortint example

Here is a full example using shortint:

{% hint style="warning" %}
Use the `--release` flag to run this example (eg: `cargo run --release`)
{% endhint %}

```rust
use tfhe::shortint::prelude::*;

fn main() {
    // We generate a set of client/server keys
    // using parameters with 2 bits of message and 2 bits of carry
    let (client_key, server_key) = gen_keys(PARAM_MESSAGE_2_CARRY_2);

    let msg1 = 1;
    let msg2 = 0;

    let modulus = client_key.parameters.message_modulus().0;

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

#### integer example

{% hint style="warning" %}
Use the `--release` flag to run this example (eg: `cargo run --release`)
{% endhint %}

```rust
use tfhe::integer::gen_keys_radix;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;

fn main() {
    // We create keys for radix represention to create 16 bits integers
    // using 8 blocks of 2 bits
    let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2, 8);

    let clear_a = 2382u16;
    let clear_b = 29374u16;

    let mut a = cks.encrypt(clear_a as u64);
    let mut b = cks.encrypt(clear_b as u64);

    let encrypted_max = sks.smart_max_parallelized(&mut a, &mut b);
    let decrypted_max: u64 = cks.decrypt(&encrypted_max);

    assert_eq!(decrypted_max as u16, clear_a.max(clear_b))
}
```

The library is simple to use and can evaluate **homomorphic circuits of arbitrary length**. The description of the algorithms can be found in the [TFHE](https://doi.org/10.1007/s00145-019-09319-x) paper (also available as [ePrint 2018/421](https://ia.cr/2018/421)).
