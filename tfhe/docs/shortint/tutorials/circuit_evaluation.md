# Circuit evaluation

Let's try to do a circuit evaluation using the different flavours of operations we already introduced.
For a very small circuit, the `unchecked` flavour may be enough to do the computation correctly.
Otherwise, the `checked` and `smart` are the best options.

As an example, let's do a scalar multiplication, a subtraction and a multiplication.


```rust
use concrete_shortint::gen_keys;
use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;

fn main() {
    // We generate a set of client/server keys, using the default parameters:
    let (client_key, server_key) = gen_keys(PARAM_MESSAGE_2_CARRY_2);

    let msg1 = 3;
    let msg2 = 3;
    let scalar = 4;
    
    let modulus = client_key.parameters.message_modulus.0;

    // We use the client key to encrypt two messages:
    let mut ct_1 = client_key.encrypt(msg1);
    let ct_2 = client_key.encrypt(msg2);
    
    server_key.unchecked_scalar_mul_assign(&mut ct_1, scalar);
    server_key.unchecked_sub_assign(&mut ct_1, &ct_2);
    server_key.unchecked_mul_lsb_assign(&mut ct_1, &ct_2);
    
    // We use the client key to decrypt the output of the circuit:
    let output = client_key.decrypt(&ct_1);
    println!("expected {}, found {}", ((msg1 * scalar as u64 - msg2) * msg2) % modulus as u64, output);
}
```

During this computation the carry buffer has been overflowed and as all the operations were `unchecked` the output
may be incorrect.

If we redo this same circuit but using the `checked` flavour, a panic will occur.

```rust
use concrete_shortint::gen_keys;
use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;
use std::error::Error;

fn main() {
    // We generate a set of client/server keys, using the default parameters:
    let (client_key, server_key) = gen_keys(PARAM_MESSAGE_2_CARRY_2);

    let msg1 = 3;
    let msg2 = 3;
    let scalar = 4;
    
    let modulus = client_key.parameters.message_modulus.0;

    // We use the client key to encrypt two messages:
    let mut ct_1 = client_key.encrypt(msg1);
    let ct_2 = client_key.encrypt(msg2);

    let mut ops = || -> Result<(), Box<dyn Error>> {
        server_key.checked_scalar_mul_assign(&mut ct_1, scalar)?;
        server_key.checked_sub_assign(&mut ct_1, &ct_2)?;
        server_key.checked_mul_lsb_assign(&mut ct_1, &ct_2)?;
        Ok(())
    };

    match ops() {
        Ok(_) => (),
        Err(e) => {
            println!("correctness of operations is not guaranteed due to error: {}", e);
            return;
        },
    }
    
    // We use the client key to decrypt the output of the circuit:
    let output = client_key.decrypt(&ct_1);
    assert_eq!(output, ((msg1 * scalar as u64 - msg2) * msg2) % modulus as u64);
}
```

Therefore the `checked` flavour permits to manually manage the overflow of the carry buffer
by raising an error if the correctness is not guaranteed.

Lastly, using the `smart` flavour will output the correct result all the time. However the computation may be slower
as the carry buffer may be cleaned during the computations.

```rust
use concrete_shortint::gen_keys;
use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;

fn main() {
    // We generate a set of client/server keys, using the default parameters:
    let (client_key, server_key) = gen_keys(PARAM_MESSAGE_2_CARRY_2);

    let msg1 = 3;
    let msg2 = 3;
    let scalar = 4;
    
    let modulus = client_key.parameters.message_modulus.0;

    // We use the client key to encrypt two messages:
    let mut ct_1 = client_key.encrypt(msg1);
    let mut ct_2 = client_key.encrypt(msg2);
    
    server_key.smart_scalar_mul_assign(&mut ct_1, scalar);
    server_key.smart_sub_assign(&mut ct_1, &mut ct_2);
    server_key.smart_mul_lsb_assign(&mut ct_1, &mut ct_2);
    
    // We use the client key to decrypt the output of the circuit:
    let output = client_key.decrypt(&ct_1);
    assert_eq!(output, ((msg1 * scalar as u64 - msg2) * msg2) % modulus as u64);
}
```
