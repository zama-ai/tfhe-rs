# Tutorial

`tfhe::shortint` is dedicated to small unsigned integers smaller than 8 bits. The steps to homomorphically evaluate a circuit are described below.

## Key generation

`tfhe::shortint` provides 3 key types:

* `ClientKey`
* `ServerKey`
* `PublicKey`

The `ClientKey` is the key that encrypts and decrypts messages (integer values up to 8 bits here). It is meant to be kept private and should never be shared. This key is created from parameter values that will dictate both the security and efficiency of computations. The parameters also set the maximum number of bits of message encrypted in a ciphertext.

The `ServerKey` is the key that is used to evaluate the FHE computations. Most importantly, it contains a bootstrapping key and a keyswitching key. This key is created from a `ClientKey` that needs to be shared to the server (it is not meant to be kept private). A user with a `ServerKey` can compute on the encrypted data sent by the owner of the associated `ClientKey`.

Computation/operation methods are tied to the `ServerKey` type.

The `PublicKey` is the key used to encrypt messages. It can be publicly shared to allow users to encrypt data such that only the `ClientKey` holder will be able to decrypt. Encrypting with the `PublicKey` does not alter the homomorphic capabilities associated to the `ServerKey`.

```rust
use tfhe::shortint::prelude::*;

fn main()  {
    // We generate a set of client/server keys
    let (client_key, server_key) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
}
```

## Encrypting values

Once the keys have been generated, the client key is used to encrypt data:

```rust
use tfhe::shortint::prelude::*;

fn main() {
    // We generate a set of client/server keys
   let (client_key, server_key) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

    let msg1 = 1;
    let msg2 = 0;

    // We use the client key to encrypt two messages:
    let ct_1 = client_key.encrypt(msg1);
    let ct_2 = client_key.encrypt(msg2);
}
```

## Encrypting values using a public key

Once the keys have been generated, the client key is used to encrypt data:

```rust
use tfhe::shortint::prelude::*;

fn main() {
    // We generate a set of client/server keys
   let (client_key, _) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
   let public_key = PublicKey::new(&client_key);

    let msg1 = 1;
    let msg2 = 0;

    // We use the client key to encrypt two messages:
    let ct_1 = public_key.encrypt(msg1);
    let ct_2 = public_key.encrypt(msg2);
}
```

## Computing and decrypting

Using the `server_key`, addition is possible over encrypted values. The resulting plaintext is recovered after the decryption via the secret client key.

```rust
use tfhe::shortint::prelude::*;

fn main() {
    // We generate a set of client/server keys
    let (client_key, server_key) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

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
