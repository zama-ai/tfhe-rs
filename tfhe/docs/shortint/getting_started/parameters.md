# Use of parameters

`concrete-shortint` comes with sets of parameters that permit to use the functionalities of the library
securely and efficiently. The user is allowed to choose which set of parameters to use when creating the pair 
of keys.


```rust
use concrete_shortint::{gen_keys, Parameters};

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

The difference between the parameter sets is the total amount of space 
dedicated to the plaintext and how it is split between
the message buffer and the carry buffer. The syntax chosen for the name of a parameter is: 
`PARAM_MESSAGE_{number of message bits}_CARRY_{number of carry bits}`. For example, the set of 
parameters for a message buffer of 5 bits and a carry buffer of 2 bits is 
`PARAM_MESSAGE_5_CARRY_2`.
