# Compute and decrypt

Computations should be as easy as normal Rust to write, thanks to the usage of operator overloading.

```Rust
let result = a + b;
```

The decryption is achieved by using the `decrypt` method, which comes from the FheDecrypt trait.

```Rust
let decrypted_result: u8 = result.decrypt(&client_key);

let clear_result = clear_a + clear_b;

assert_eq!(decrypted_result, clear_result);
```
