# Tutorial

`tfhe::integer` is dedicated to integers smaller than 256 bits. The steps to homomorphically evaluate an integer circuit are described here.

## Key Types

`integer` provides 3 basic key types:

* `ClientKey`
* `ServerKey`
* `CompactPublicKey`

The `ClientKey` is the key that encrypts and decrypts messages, thus this key is meant to be kept private and should never be shared. This key is created from parameter values that will dictate both the security and efficiency of computations. The parameters also set the maximum number of bits of message encrypted in a ciphertext.

The `ServerKey` is the key that is used to actually do the FHE computations. It contains a bootstrapping key and a keyswitching key. This key is created from a `ClientKey` that needs to be shared to the server, so it is not meant to be kept private. A user with a `ServerKey` can compute on the encrypted data sent by the owner of the associated `ClientKey`.

To reflect this, computation/operation methods are tied to the `ServerKey` type.

The `CompactPublicKey` is a key used to encrypt messages. It can be publicly shared to allow users to encrypt data such that only the holder of the associated private key will be able to decrypt. It is generated from a dedicated `CompactPrivateKey`: data encrypted with the `CompactPublicKey` is encrypted under this private key, as a `CompactCiphertextList`. When the list is expanded, a `KeySwitchingKey` converts the ciphertexts so they are encrypted under the `ClientKey`, and they can then be used with the associated `ServerKey`.

## 1. Key Generation

To generate the keys, a user needs two parameters:

* A set of `shortint` cryptographic parameters.
* The number of ciphertexts used to encrypt an integer (we call them "shortint blocks").

We are now going to build a pair of keys that can encrypt **8-bit** integers (signed or unsigned) by using **4** shortint blocks that store **2** bits of message each.

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

Once the client key is generated, a compact public key can be created and used to encrypt data.

```rust
use tfhe::integer::ciphertext::CompactCiphertextList;
use tfhe::integer::key_switching_key::KeySwitchingKey;
use tfhe::integer::parameters::IntegerCompactCiphertextListExpansionMode;
use tfhe::integer::{gen_keys_radix, CompactPrivateKey, CompactPublicKey, RadixCiphertext};
use tfhe::shortint::parameters::{
    PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128, PARAM_MESSAGE_2_CARRY_2_KS_PBS,
    PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};

fn main() {
    // We generate a set of client/server keys, using the default parameters:
    let num_block = 4;
    let (client_key, server_key) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_block);

    // We generate the compact public key from its own private key:
    let cpk_private_key = CompactPrivateKey::new(PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128);
    let public_key = CompactPublicKey::new(&cpk_private_key);

    // The casting key converts ciphertexts encrypted under the compact public key
    // into ciphertexts usable with the server key:
    let casting_key = KeySwitchingKey::new(
        (&cpk_private_key, None),
        (&client_key, &server_key),
        PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    );

    let msg1 = 128u64;
    let msg2 = 13u64;

    // We use the public key to encrypt two messages:
    let compact_list = CompactCiphertextList::builder(&public_key)
        .push_with_num_blocks(msg1, num_block)
        .push_with_num_blocks(msg2, num_block)
        .build();

    // The list is then expanded into ciphertexts usable with the server key:
    let expansion_mode =
        IntegerCompactCiphertextListExpansionMode::CastAndUnpackIfNecessary(casting_key.as_view());
    let expander = compact_list.expand(expansion_mode).unwrap();
    let ct_1: RadixCiphertext = expander.get(0).unwrap().unwrap();
    let ct_2: RadixCiphertext = expander.get(1).unwrap().unwrap();

    let dec_1: u64 = client_key.decrypt(&ct_1);
    let dec_2: u64 = client_key.decrypt(&ct_2);
    assert_eq!(dec_1, msg1);
    assert_eq!(dec_2, msg2);
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
    let modulus = client_key.parameters().message_modulus().0.pow(num_block as u32);

    // We use the client key to encrypt two messages:
    let ct_1 = client_key.encrypt(msg1);
    let ct_2 = client_key.encrypt(msg2);

    // We use the server public key to execute an integer circuit:
    let ct_3 = server_key.add_parallelized(&ct_1, &ct_2);

    // We use the client key to decrypt the output of the circuit:
    let output: u64 = client_key.decrypt(&ct_3);

    assert_eq!(output, (msg1 + msg2) % modulus);
}
```
