# Decrypt data

Decrypting data is achieved by using the `decrypt` method, which comes from the FheDecrypt trait.

```rust
use tfhe::prelude::*;
use tfhe::{generate_keys, ConfigBuilder, FheUint8};

fn main() {
    let config = ConfigBuilder::default().build();

    let (client_key, server_key) = generate_keys(config);

    let clear_a = 27u8;
    let clear_b = 128u8;

    let a = FheUint8::encrypt(clear_a, &client_key);
    let b = FheUint8::encrypt(clear_b, &client_key);

    let decrypted_a: u8 = a.decrypt(&client_key);
    let decrypted_b: u8 = b.decrypt(&client_key);

    assert_eq!(decrypted_a, clear_a);
    assert_eq!(decrypted_b, clear_b);
}
```
