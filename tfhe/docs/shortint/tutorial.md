# Tutorial: Writing an homomorphic circuit using shortints

# 1. Key Generation

`tfhe::shortint` provides 2 key types:
 - `ClientKey`
 - `ServerKey`

The `ClientKey` is the key that encrypts and decrypts messages (integer values up to 8 bits here),
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


```rust
use tfhe::shortint::prelude::*;

fn main()  {
    // We generate a set of client/server keys, using the default parameters:
    let (client_key, server_key) = gen_keys(Parameters::default());
}
```


# 2. Encrypting values

Once the keys have been generated, the client key is used to encrypt data:

```rust
use tfhe::shortint::prelude::*;

fn main() {
    // We generate a set of client/server keys, using the default parameters:
   let (client_key, server_key) = gen_keys(Parameters::default());
   
    let msg1 = 1;
    let msg2 = 0;
   
    // We use the client key to encrypt two messages:
    let ct_1 = client_key.encrypt(msg1);
    let ct_2 = client_key.encrypt(msg2);
}
```

# 2 bis. Encrypting values using a public key

Once the keys have been generated, the client key is used to encrypt data:

```rust
use tfhe::shortint::prelude::*;

fn main() {
    // We generate a set of client/server keys, using the default parameters:
   let (client_key, server_key) = gen_keys(Parameters::default());
   let public_key = PublicKey::new(&client_key);
    
    let msg1 = 1;
    let msg2 = 0;
   
    // We use the client key to encrypt two messages:
    let ct_1 = public_key.encrypt(&server_key, msg1);
    let ct_2 = public_key.encrypt(&server_key, msg2);
}
```


# 3. Computing and decrypting

With our `server_key`, and encrypted values, we can now do an addition
and then decrypt the result.

```rust
use tfhe::shortint::prelude::*;

fn main() {
    // We generate a set of client/server keys, using the default parameters:
    let (client_key, server_key) = gen_keys(Parameters::default());

    let msg1 = 1;
    let msg2 = 0;
    
    let modulus = client_key.parameters.message_modulus.0;

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
