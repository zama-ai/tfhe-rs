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

### Boolean example.

Here is an example to illustrate how the library can be used to evaluate a Boolean circuit:

```rust
use tfhe::boolean::prelude::*;

fn main() {
// We generate a set of client/server keys, using the default parameters:
    let (mut client_key, mut server_key) = gen_keys();

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

### Shortint example.

And here is a full example using shortint:

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

The library is pretty simple to use, and can evaluate **homomorphic circuits of arbitrary length**. The description of the algorithms can be found in the [TFHE](https://doi.org/10.1007/s00145-019-09319-x) paper (also available as [ePrint 2018/421](https://ia.cr/2018/421)).
