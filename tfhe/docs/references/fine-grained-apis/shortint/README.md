# Tutorial

`tfhe::shortint` is dedicated to the manipulation of small unsigned integers that fit in a single [LWE ciphertext](../../../getting-started/security-and-cryptography.md#lwe-ciphertexts). The actual size depends on the chosen parameters, but is always smaller than 8 bits. For example, with the `PARAM_MESSAGE_2_CARRY_2_KS_PBS` parameters, you can encode messages of 2 bits inside a `shortint`.

The [integer](../integer/README.md) and [high-level](../quick-start.md#high-level-api) API leverage shortints to allow homomorphic computations over larger integers.

The steps to homomorphically evaluate a `shortint` circuit are described below.

## Key generation

`tfhe::shortint` provides 3 key types:

* `ClientKey`
* `ServerKey`
* `CompactPublicKey`

The `ClientKey` is the key that encrypts and decrypts messages (small integer values). It is meant to be kept private and should never be shared. This key is created from parameter values that will dictate both the security and efficiency of computations. The parameters also set the maximum number of bits of message encrypted in a ciphertext.

The `ServerKey` is the key that is used to evaluate the FHE computations. Most importantly, it contains a bootstrapping key and a keyswitching key. This key is created from a `ClientKey` that needs to be shared to the server (it is not meant to be kept private). A user with a `ServerKey` can compute on the encrypted data sent by the owner of the associated `ClientKey`.

Computation/operation methods are tied to the `ServerKey` type.

The `CompactPublicKey` is the key used to encrypt messages. It can be publicly shared to allow users to encrypt data such that only the holder of the associated private key will be able to decrypt. It is generated from a dedicated `CompactPrivateKey`: data encrypted with the `CompactPublicKey` is encrypted under this private key, as a `CompactCiphertextList`. When the list is expanded, a `KeySwitchingKey` converts the ciphertexts so they are encrypted under the `ClientKey`, and they can then be used with the associated `ServerKey`.

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

Data can also be encrypted with a `CompactPublicKey`:

```rust
use tfhe::shortint::parameters::{
    PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use tfhe::shortint::prelude::*;
use tfhe::shortint::CompactPrivateKey;

fn main() {
    // Generate the client key and the server key:
    let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

    // Generate the compact public key from its own private key:
    let cpk_private_key = CompactPrivateKey::new(PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
    let cpk = CompactPublicKey::new(&cpk_private_key);

    // The casting key converts ciphertexts encrypted under the compact public key
    // into ciphertexts usable with the server key:
    let casting_key = KeySwitchingKey::new(
        (&cpk_private_key, None),
        (&cks, &sks),
        PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    );

    let msg = 2;
    // Encryption of one message:
    let compact_list = cpk.encrypt_slice(&[msg]);
    let cts = compact_list.expand(casting_key.as_view(), None).unwrap();
    // Decryption:
    let dec = cks.decrypt(&cts[0]);
    assert_eq!(dec, msg);
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

    let modulus = client_key.parameters().message_modulus().0;

    // We use the client key to encrypt two messages:
    let ct_1 = client_key.encrypt(msg1);
    let ct_2 = client_key.encrypt(msg2);

    // We use the server public key to execute an integer circuit:
    let ct_3 = server_key.add(&ct_1, &ct_2);

    // We use the client key to decrypt the output of the circuit:
    let output = client_key.decrypt(&ct_3);
    assert_eq!(output, (msg1 + msg2) % modulus);
}
```
