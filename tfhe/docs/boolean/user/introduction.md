# Introduction

Welcome to the `concrete-boolean` guide!

This library makes it possible to execute **boolean gates over encrypted bits**.
It allows one to execute a boolean circuit on an **untrusted server** because both circuit inputs and
outputs are kept **private**.
Data are indeed encrypted on the client side, before being sent to the server.
On the server side every computation is performed on ciphertexts.

The server however has to know the boolean circuit to be evaluated.
At the end of the computation, the server returns the encryption of the result to the user.
She can then decrypt it with her `secret key`.

The library is pretty simple to use, and can evaluate **homomorphic boolean circuits of arbitrary
length**.

Here is a quick example of how the library can be used:

```rust
extern crate concrete_boolean;
use concrete_boolean::prelude::*;
use concrete_boolean::gen_keys;

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
```

As simple as that! If you are hooked, jump to the next section!
