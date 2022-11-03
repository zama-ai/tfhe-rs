# Operation lists

In what follows, the operation associated to each type (Booleans and shortints) are listed.

## Booleans

The list of supported operations by the homomorphic booleans is:

|Operation Name | type    |
| ------        | ------  |
| `not`         | Unary   |
| `and`         | Binary  |
| `or`          | Binary  |
| `xor`         | Binary  |
| `nor`         | Binary  |
| `xnor`        | Binary  |
| `cmux`        | Ternary |


A simple example on how to use these operations:

```rust
use tfhe::boolean::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {

    //Key Generation

    let (cks, sks) = gen_keys();

    //Clear messages

    let clear1 = true;

    let clear2 = false;

    let clear_true = true;

    //Encryption of the clears using the client key

    let ct1 = cks.encrypt(clear1);

    let ct2 = cks.encrypt(clear2);

    //Homomorphic operations using the server keuy

    let not_ct1 = sks.not(&ct1);

    let not_ct1_xor_ct2 = sks.xor(&not_ct1, &ct2);

    let ct_result = sks.and(&not_ct1_xor_ct2, clear_true);

    //Decryption using the client key

    let clear_result = cks.decrypt(&ct_result);

    assert_eq!(clear_result, (!clear1^clear2)&clear_true);
    
    Ok(())

}

```

A walk-through using homomorphic Booleans can be found [here](../Booleans/tutorial.md).


## ShortInt

In TFHE.rs, the shortints represent small integers encoded over 8 bits maximum.
A complete homomorphic arithmetic is provided, along with the possibility to compute
univariate and bivariate functions. Some operations are only available for integers
up to 4 bits. More technical details can be found [here](../shortint/operations.md).


The list of supported operations is:

| Operation name              | Type         |
|---------------              | ------       |
| Negation                    | Unary        |
| Addition                    | Binary       |
| Subtraction                 | Binary       |
| Multiplication              | Binary       |
| Division*                   | Binary       |
| Modular reduction           | Binary       |
| Comparisons                 | Binary       |
| Left/Right Shift            | Binary       |
| And                         | Binary       |
| Or                          | Binary       |
| Xor                         | Binary       |
| Exact Function Evaluation   | Unary/Binary |

*The division operation implements a subtlety: since data is encrypted, it might be possible to
compute a division by 0. In this case, the division is tweaked so that dividing by 0 returns 0.

In what follows, a simple example basic operations and a function evaluation.

### Arithmetic operations

A simple example on how to use common operations:
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
    let ct_4 = server_key.unchecked_scalar_left_shift(&ct_3, 1);
    
    // We evaluate the function f(x) = x^2
    let acc = server_key.generate_accumulator(|x|x*x % modulus as u64);
    let ct_5 = server_key.keyswitch_programmable_bootstrap(&ct_4, &acc);
    
    // We use the client key to decrypt the output of the circuit:
    let output = client_key.decrypt(&ct_5);
    let check_res = ( ((msg1 + msg2) << 1) * ((msg1 + msg2) << 1)) % modulus as u64;
    assert_eq!(output, check_res);
}
```

A walk-through example can be found [here](../shortint/tutorial.md) and more examples and 
explanations can be found [here](../shortint/operations.md)





