# Tutorial

`tfhe::integer` is dedicated to unsigned integers smaller than 256 bits. The steps to homomorphically evaluate an integer circuit are described here.

## Key Types

`integer` provides 3 basic key types:

* `ClientKey`
* `ServerKey`
* `PublicKey`

The `ClientKey` is the key that encrypts and decrypts messages, thus this key is meant to be kept private and should never be shared. This key is created from parameter values that will dictate both the security and efficiency of computations. The parameters also set the maximum number of bits of message encrypted in a ciphertext.

The `ServerKey` is the key that is used to actually do the FHE computations. It contains a bootstrapping key and a keyswitching key. This key is created from a `ClientKey` that needs to be shared to the server, so it is not meant to be kept private. A user with a `ServerKey` can compute on the encrypted data sent by the owner of the associated `ClientKey`.

To reflect this, computation/operation methods are tied to the `ServerKey` type.

The `PublicKey` is a key used to encrypt messages. It can be publicly shared to allow users to encrypt data such that only the `ClientKey` holder will be able to decrypt. Encrypting with the `PublicKey` does not alter the homomorphic capabilities associated to the `ServerKey`.

## 1. Key Generation

To generate the keys, a user needs two parameters:

* A set of `shortint` cryptographic parameters.
* The number of ciphertexts used to encrypt an integer (we call them "shortint blocks").

We are now going to build a pair of keys that can encrypt an **8-bit** integer by using **4** shortint blocks that store **2** bits of message each.

```rust
use tfhe::integer::gen_keys_radix;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

fn main() {
    // We generate a set of client/server keys, using the default parameters:
    let num_block = 4;
    let (client_key, server_key) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_block);
}
```

## 2. Encrypting values

Once we have our keys, we can encrypt values:

```rust
use tfhe::integer::gen_keys_radix;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

fn main() {
    // We generate a set of client/server keys, using the default parameters:
    let num_block = 4;
    let (client_key, server_key) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_block);

    let msg1 = 128u64;
    let msg2 = 13u64;

    // We use the client key to encrypt two messages:
    let ct_1 = client_key.encrypt(msg1);
    let ct_2 = client_key.encrypt(msg2);
}
```

## 3. Encrypting values with the public key

Once the client key is generated, the public key can be derived and used to encrypt data.

```rust
use tfhe::integer::gen_keys_radix;
use tfhe::integer::PublicKey;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

fn main() {
    // We generate a set of client/server keys, using the default parameters:
    let num_block = 4;
    let (client_key, _) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_block);

    //We generate the public key from the secret client key:
    let public_key = PublicKey::new(&client_key);

    //encryption
    let msg1 = 128u64;
    let msg2 = 13u64;

    // We use the public key to encrypt two messages:
    let ct_1 = public_key.encrypt_radix(msg1, num_block);
    let ct_2 = public_key.encrypt_radix(msg2, num_block);
}
```

## 4. Computing and decrypting

With our `server_key`, and encrypted values, we can now do an addition and then decrypt the result.

```rust
use tfhe::integer::gen_keys_radix;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

fn main() {
    // We generate a set of client/server keys, using the default parameters:
    let num_block = 4;
    let (client_key, server_key) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_block);

    let msg1 = 128;
    let msg2 = 13;

    // message_modulus^vec_length
    let modulus = client_key.parameters().message_modulus().0.pow(num_block as u32) as u64;

    // We use the client key to encrypt two messages:
    let ct_1 = client_key.encrypt(msg1);
    let ct_2 = client_key.encrypt(msg2);

    // We use the server public key to execute an integer circuit:
    let ct_3 = server_key.unchecked_add(&ct_1, &ct_2);

    // We use the client key to decrypt the output of the circuit:
    let output: u64 = client_key.decrypt(&ct_3);

    assert_eq!(output, (msg1 + msg2) % modulus);
}
```
