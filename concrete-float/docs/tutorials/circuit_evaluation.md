# Circuit evaluation

Let's try to do a circuit evaluation using the different flavours of operations we already introduced.
For a very small circuit, the `unchecked` flavour may be enough to do the computation correctly.
Otherwise, the `checked` and `smart` are the best options.

As an example, let's do a scalar multiplication, a subtraction and an addition.


```rust
use concrete_integer::gen_keys;
use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;

fn main() {
    let num_block = 4;
    let (client_key, server_key) = gen_keys(&PARAM_MESSAGE_2_CARRY_2, num_block);

    let msg1 = 12;
    let msg2 = 11;
    let msg3 = 9;
    let scalar = 3;

    // message_modulus^vec_length
    let modulus = client_key.parameters().message_modulus.0.pow(num_block as u32) as u64;

    // We use the client key to encrypt two messages:
    let mut ct_1 = client_key.encrypt(msg1);
    let ct_2 = client_key.encrypt(msg2);
    let ct_3 = client_key.encrypt(msg2);
    
    server_key.unchecked_small_scalar_mul_assign(&mut ct_1, scalar);
    
    server_key.unchecked_sub_assign(&mut ct_1, &ct_2);
    
    server_key.unchecked_add_assign(&mut ct_1, &ct_3);
    
    // We use the client key to decrypt the output of the circuit:
    let output = client_key.decrypt(&ct_1);
    // The carry buffer has been overflowed, the result is not correct
    assert_ne!(output, ((msg1 * scalar as u64 - msg2) + msg3) % modulus as u64);
}
```

During this computation the carry buffer has been overflowed and as all the operations were `unchecked` the output
may be incorrect.

If we redo this same circuit but using the `checked` flavour, a panic will occur.

```rust
use concrete_integer::gen_keys;
use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;

fn main() {
    let num_block = 2;
    let (client_key, server_key) = gen_keys(&PARAM_MESSAGE_2_CARRY_2, num_block);

    let msg1 = 12;
    let msg2 = 11;
    let msg3 = 9;
    let scalar = 3;

    // message_modulus^vec_length
    let modulus = client_key.parameters().message_modulus.0.pow(num_block as u32) as u64;

    // We use the client key to encrypt two messages:
    let mut ct_1 = client_key.encrypt(msg1);
    let ct_2 = client_key.encrypt(msg2);
    let ct_3 = client_key.encrypt(msg3);
    
    let result = server_key.checked_small_scalar_mul_assign(&mut ct_1, scalar);
    assert!(result.is_ok());

    let result = server_key.checked_sub_assign(&mut ct_1, &ct_2);
    assert!(result.is_err());
    
    // We use the client key to decrypt the output of the circuit:
    // Only the scalar multiplication could be done
    let output = client_key.decrypt(&ct_1);
    assert_eq!(output, (msg1 * scalar) % modulus as u64);
}
```

Therefore the `checked` flavour permits to manually manage the overflow of the carry buffer
by raising an error if the correctness is not guaranteed.

Lastly, using the `smart` flavour will output the correct result all the time. However, the computation may be slower
as the carry buffer may be propagated during the computations.

```rust
use concrete_integer::gen_keys;
use concrete_shortint::parameters::PARAM_MESSAGE_2_CARRY_2;

fn main() {
    let num_block = 4;
    let (client_key, server_key) = gen_keys(&PARAM_MESSAGE_2_CARRY_2, num_block);

    let msg1 = 12;
    let msg2 = 11;
    let msg3 = 9;
    let scalar = 3;

    // message_modulus^vec_length
    let modulus = client_key.parameters().message_modulus.0.pow(num_block as u32) as u64;

    // We use the client key to encrypt two messages:
    let mut ct_1 = client_key.encrypt(msg1);
    let mut ct_2 = client_key.encrypt(msg2);
    let mut ct_3 = client_key.encrypt(msg3);
    
    server_key.smart_scalar_mul_assign(&mut ct_1, scalar);
    
    server_key.smart_sub_assign(&mut ct_1, &mut ct_2);
    
    server_key.smart_add_assign(&mut ct_1, &mut ct_3);
    
    // We use the client key to decrypt the output of the circuit:
    let output = client_key.decrypt(&ct_1);
    assert_eq!(output, ((msg1 * scalar as u64 - msg2) + msg3) % modulus as u64);
}
```