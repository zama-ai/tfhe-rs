# Encrypt data

Encrypting data is achieved via the `encrypt` associated function of the FheEncrypt trait.

Types exposed by this crate implement at least one of FheEncrypt or FheTryEncrypt to allow encryption.

```Rust
let clear_a = 27u8;
let clear_b = 128u8;

let a = FheUint8::encrypt(clear_a, &client_key);
let b = FheUint8::encrypt(clear_b, &client_key);
```
