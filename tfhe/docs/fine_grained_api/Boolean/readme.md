# Tutorial

In `tfhe::boolean`, the available operations are mainly related to their equivalent Boolean gates (i.e., AND, OR... etc). What follows are examples of a unary gate (NOT) and a binary gate (XOR). The last one is about the ternary MUX gate, which allows homomorphic computation of conditional statements of the form `If..Then..Else`.


This library is meant to be used both on the **server side** and the **client side**. The typical use case should follow the subsequent steps:

1. On the **client side**, generate the `client` and `server keys`.
2. Send the `server key` to the **server**.
3. Then any number of times:
   * On the **client side**, _encrypt_ the input data with the `client key`.
   * Transmit the encrypted input to the **server**.
   * On the **server side**, perform _homomorphic computation_ with the `server key`.
   * Transmit the encrypted output to the **client**.
   * On the **client side**, _decrypt_ the output data with the `client key`.

## Setup

In the first step, the client creates two keys, the `client key` and the `server key`, with the `concrete_boolean::gen_keys` function:

```rust
use tfhe::boolean::prelude::*;

fn main() {

// We generate the client key and the server key,
// using the default parameters:
    let (client_key, server_key): (ClientKey, ServerKey) = gen_keys();
}
```

* The `client_key` is of type `ClientKey`. It is **secret** and must **never** be transmitted. This key will only be used to encrypt and decrypt data.
* The `server_key` is of type `ServerKey`. It is a **public key** and can be shared with any party. This key has to be sent to the server because it is required for homomorphic computation.

Note that both the `client_key` and `server_key` implement the `Serialize` and `Deserialize` traits. This way you can use any compatible serializer to store/send the data. To store the `server_key` in a binary file, you can use the `bincode` library:

```rust
use std::fs::File;
use std::io::{Write, Read};
use tfhe::boolean::prelude::*;

fn main() {

//---------------------------- CLIENT SIDE ----------------------------

// We generate a client key and a server key, using the default parameters:
    let (client_key, server_key) = gen_keys();

// We serialize the server key to bytes, and store them in a file:
    let encoded: Vec<u8> = bincode::serialize(&server_key).unwrap();

    let server_key_file = "/tmp/tutorial_server_key.bin";

// We write the server key to a file:
    let mut file = File::create(server_key_file)
        .expect("failed to create server key file");
    file.write_all(encoded.as_slice()).expect("failed to write key to file");

// ...
// We send the key to server side
// ...


//---------------------------- SERVER SIDE ----------------------------

// We read the file:
    let mut file = File::open(server_key_file)
        .expect("failed to open server key file");
    let mut encoded: Vec<u8> = Vec::new();
    file.read_to_end(&mut encoded).expect("failed to read key");

// We deserialize the server key:
    let key: ServerKey = bincode::deserialize(&encoded[..])
        .expect("failed to deserialize");
}
```

## Encrypting inputs

Once the server key is available on the **server side**, it is possible to perform some homomorphic computations. The client needs to encrypt some data and send it to the server. Again, the `Ciphertext` type implements the `Serialize` and the `Deserialize` traits, so that any serializer and communication tool suiting your use case can be employed:

```rust
use tfhe::boolean::prelude::*;

fn main() {
    // Don't consider the following line; you should follow the procedure above.
    let (client_key, _) = gen_keys();

//---------------------------- SERVER SIDE

// We use the client key to encrypt the messages:
    let ct_1 = client_key.encrypt(true);
    let ct_2 = client_key.encrypt(false);

// We serialize the ciphertexts:
    let encoded_1: Vec<u8> = bincode::serialize(&ct_1).unwrap();
    let encoded_2: Vec<u8> = bincode::serialize(&ct_2).unwrap();

// ...
// And we send them to the server somehow
// ...
}
```

## Encrypting inputs using a public key

Once the server key is available on the **server side**, it is possible to perform some homomorphic computations. The client simply needs to encrypt some data and send it to the server. Again, the `Ciphertext` type implements the `Serialize` and the `Deserialize` traits, so that any serializer and communication tool suiting your use case can be utilized:

```rust
use tfhe::boolean::prelude::*;

fn main() {
    // Don't consider the following line; you should follow the procedure above.
    let (client_key, _) = gen_keys();
    let public_key = PublicKey::new(&client_key);

//---------------------------- SERVER SIDE

// We use the public key to encrypt the messages:
    let ct_1 = public_key.encrypt(true);
    let ct_2 = public_key.encrypt(false);

// We serialize the ciphertexts:
    let encoded_1: Vec<u8> = bincode::serialize(&ct_1).unwrap();
    let encoded_2: Vec<u8> = bincode::serialize(&ct_2).unwrap();

// ...
// And we send them to the server somehow
// ...
}
```

## Executing a Boolean circuit

Once the encrypted inputs are on the **server side**, the `server_key` can be used to homomorphically execute the desired Boolean circuit:

```rust
use std::fs::File;
use std::io::{Write, Read};
use tfhe::boolean::prelude::*;

fn main() {
    // Don't consider the following lines; you should follow the procedure above.
    let (client_key, server_key) = gen_keys();
    let ct_1 = client_key.encrypt(true);
    let ct_2 = client_key.encrypt(false);
    let encoded_1: Vec<u8> = bincode::serialize(&ct_1).unwrap();
    let encoded_2: Vec<u8> = bincode::serialize(&ct_2).unwrap();

//---------------------------- ON SERVER SIDE ----------------------------

// We deserialize the ciphertexts:
    let ct_1: Ciphertext = bincode::deserialize(&encoded_1[..])
        .expect("failed to deserialize");
    let ct_2: Ciphertext = bincode::deserialize(&encoded_2[..])
        .expect("failed to deserialize");

// We use the server key to execute the boolean circuit:
// if ((NOT ct_2) NAND (ct_1 AND ct_2)) then (NOT ct_2) else (ct_1 AND ct_2)
    let ct_3 = server_key.not(&ct_2);
    let ct_4 = server_key.and(&ct_1, &ct_2);
    let ct_5 = server_key.nand(&ct_3, &ct_4);
    let ct_6 = server_key.mux(&ct_5, &ct_3, &ct_4);

// Then we serialize the output of the circuit:
    let encoded_output: Vec<u8> = bincode::serialize(&ct_6)
        .expect("failed to serialize output");

// ...
// And we send the output to the client
// ...
}
```

## Decrypting the output

Once the encrypted output is on the client side, the `client_key` can be used to decrypt it:

```rust
use std::fs::File;
use std::io::{Write, Read};
use tfhe::boolean::prelude::*;

fn main() {
    // Don't consider the following lines; you should follow the procedure above.
    let (client_key, server_key) = gen_keys();
    let ct_6 = client_key.encrypt(true);
    let encoded_output: Vec<u8> = bincode::serialize(&ct_6).unwrap();

//---------------------------- ON CLIENT SIDE

// We deserialize the output ciphertext:
    let output: Ciphertext = bincode::deserialize(&encoded_output[..])
        .expect("failed to deserialize");

// Finally, we decrypt the output:
    let output = client_key.decrypt(&output);

// And check that the result is the expected one:
    assert_eq!(output, true);
}
```
