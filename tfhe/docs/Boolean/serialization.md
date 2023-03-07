# Save and Load Keys From Files

Since the `ServerKey` and `ClientKey` types both implement the `Serialize` and
`Deserialize` traits, you are free to use any serializer that suits you to save and load the
keys to disk.

Here is an example using the `bincode` serialization library, which serializes to a
binary format:

```rust
use std::fs::File;
use std::io::{Write, Read};
use tfhe::boolean::prelude::*;

fn main() {
// We generate a set of client/server keys, using the default parameters:
    let (client_key, server_key) = gen_keys();

// We serialize the keys to bytes:
    let encoded_server_key: Vec<u8> = bincode::serialize(&server_key).unwrap();
    let encoded_client_key: Vec<u8> = bincode::serialize(&client_key).unwrap();

    let server_key_file = "/tmp/ser_example_server_key.bin";
    let client_key_file = "/tmp/ser_example_client_key.bin";

// We write the keys to files:
    let mut file = File::create(server_key_file)
        .expect("failed to create server key file");
    file.write_all(encoded_server_key.as_slice()).expect("failed to write key to file");
    let mut file = File::create(client_key_file)
        .expect("failed to create client key file");
    file.write_all(encoded_client_key.as_slice()).expect("failed to write key to file");

// We retrieve the keys:
    let mut file = File::open(server_key_file)
        .expect("failed to open server key file");
    let mut encoded_server_key: Vec<u8> = Vec::new();
    file.read_to_end(&mut encoded_server_key).expect("failed to read the key");

    let mut file = File::open(client_key_file)
        .expect("failed to open client key file");
    let mut encoded_client_key: Vec<u8> = Vec::new();
    file.read_to_end(&mut encoded_client_key).expect("failed to read the key");

// We deserialize the keys:
    let loaded_server_key: ServerKey = bincode::deserialize(&encoded_server_key[..])
        .expect("failed to deserialize");
    let loaded_client_key: ClientKey = bincode::deserialize(&encoded_client_key[..])
        .expect("failed to deserialize");


    let ct_1 = client_key.encrypt(false);

// We check for equality:
    assert_eq!(false, loaded_client_key.decrypt(&ct_1));
}
```
