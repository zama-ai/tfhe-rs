# Trival Ciphertext

Sometimes, the server side needs to initialize a value.
For example, when computing the sum of a list of ciphertext,
one might want to initialize the `sum` variable to `0`.

Instead of asking the client to send a real encryption of zero,
the server can do a *trivial encryption*

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8};

let config = ConfigBuilder::all_disabled()
    .enable_default_integers()
    .build();
let (client_key, sks) = generate_keys(config);

set_server_key(sks);

let a = FheUint8::try_encrypt_trivial(234u8).unwrap();

let clear: u8 = a.decrypt(&client_key);
assert_eq!(clear, 234);
```

A *trivial encryption* will create a ciphertext that contains
the desired value, however, the 'encryption' is trivial that is,
it is not really encrypted: anyone, any key can decrypt it.

Note that when you want to do an operation that involves a ciphertext
and a clear value, you should only use a trivial encryption of the clear
value if the ciphertext/clear-value operation (often called scalar operation) you want to run is not supported.

### Example

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint32};

let config = ConfigBuilder::all_disabled()
    .enable_default_integers()
    .build();
let (client_key, sks) = generate_keys(config);

set_server_key(sks);

// This is going to be faster
let a = FheUint32::try_encrypt(2097152u32, &client_key).unwrap();
let shift = 1u32;
let shifted = a << shift;
let clear: u32 = shifted.decrypt(&client_key);
assert_eq!(clear, 2097152 << 1);

// This is going to be slower
let a = FheUint32::try_encrypt(2097152u32, &client_key).unwrap();
let shift = FheUint32::try_encrypt_trivial(1).unwrap();
let shifted = a << shift;
let clear: u32 = shifted.decrypt(&client_key);
assert_eq!(clear, 2097152 << 1);
```
