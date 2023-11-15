# Writing Your First Circuit


## Key Types

`concrete-integer` provides 2 basic key types:
 - `ClientKey`
 - `ServerKey`
 
The `ClientKey` is the key that encrypts and decrypts messages,
thus this key is meant to be kept private and should never be shared. 
This key is created from parameter values that will dictate both the security and efficiency 
of computations. The parameters also set the maximum number of bits of message encrypted 
in a ciphertext.

The `ServerKey` is the key that is used to actually do the FHE computations. It contains (among other things)
a bootstrapping key and a keyswitching key.
This key is created from a `ClientKey` that needs to be shared to the server, therefore it is not 
meant to be kept private.
A user with a `ServerKey` can compute on the encrypted data sent by the owner of the associated 
`ClientKey`.

To reflect that, computation/operation methods are tied to the `ServerKey` type.


## 1. Key Generation

To generate the keys, a user needs two parameters:
  - A set of `shortint` cryptographic parameters.
  - The number of ciphertexts used to encrypt an integer (we call them "shortint blocks").


For this example we are going to build a pair of keys that can encrypt an **8-bit** integer
by using **4** shortint blocks that store **2** bits of message each.


```rust
use concrete_integer::gen_keys;
use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;

fn main() {
    // We generate a set of client/server keys, using the default parameters:
    let num_block = 4;
    let (client_key, server_key) = gen_keys(&PARAM_MESSAGE_2_CARRY_2, num_block);
}
```



## 2. Encrypting values


Once we have our keys we can encrypt values:

```rust
use concrete_integer::gen_keys;
use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;

fn main() {
    // We generate a set of client/server keys, using the default parameters:
    let num_block = 4;
    let (client_key, server_key) = gen_keys(&PARAM_MESSAGE_2_CARRY_2, num_block);
   
    let msg1 = 128;
    let msg2 = 13;
   
    // We use the client key to encrypt two messages:
    let ct_1 = client_key.encrypt(msg1);
    let ct_2 = client_key.encrypt(msg2);
}
```

## 3. Computing and decrypting

With our `server_key`, and encrypted values, we can now do an addition
and then decrypt the result.

```rust
use concrete_integer::gen_keys;
use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;

fn main() {
    // We generate a set of client/server keys, using the default parameters:
    let num_block = 4;
    let (client_key, server_key) = gen_keys(&PARAM_MESSAGE_2_CARRY_2, num_block);

    let msg1 = 128;
    let msg2 = 13;

    // message_modulus^vec_length
    let modulus = client_key.parameters().message_modulus.0.pow(num_block as u32) as u64;
    
    // We use the client key to encrypt two messages:
    let ct_1 = client_key.encrypt(msg1);
    let ct_2 = client_key.encrypt(msg2);
    
    // We use the server public key to execute an integer circuit:
    let ct_3 = server_key.unchecked_add(&ct_1, &ct_2);
    
    // We use the client key to decrypt the output of the circuit:
    let output = client_key.decrypt(&ct_3);

    assert_eq!(output, (msg1 + msg2) % modulus);
}
```
