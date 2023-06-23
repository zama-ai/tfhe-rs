# Cryptographic Parameters

All parameter sets provide at least 128-bits of security according to the [Lattice-Estimator](https://github.com/malb/lattice-estimator), with an error probability equal to $$2^{-40}$$ when using programmable bootstrapping. This error probability is due to the randomness added at each encryption (see [here](../../getting_started/security_and_cryptography.md) for more details about the encryption process).

## Parameters and message precision

`shortint` comes with sets of parameters that permit the use of the library functionalities securely and efficiently. Each parameter set is associated to the message and carry precisions. Therefore, each key pair is entangled to precision.

The user is allowed to choose which set of parameters to use when creating the pair of keys.

The difference between the parameter sets is the total amount of space dedicated to the plaintext, how it is split between the message buffer and the carry buffer, and the order in which the keyswitch (KS) and bootstrap (PBS) are computed. The syntax chosen for the name of a parameter is: `PARAM_MESSAGE_{number of message bits}_CARRY_{number of carry bits}_{KS_PBS | PBS_KS}`. For example, the set of parameters for a message buffer of 5 bits, a carry buffer of 2 bits and where the keyswitch is computed before the bootstrap is `PARAM_MESSAGE_5_CARRY_2_KS_PBS`.

Note that the `KS_PBS` order should have better performance at the expense of ciphertext size, `PBS_KS` is the opposite.

This example contains keys that are generated to have messages encoded over 2 bits (i.e., computations are done modulus $$2^2 = 4$$) with 2 bits of carry.

The `PARAM_MESSAGE_2_CARRY_2_KS_PBS` parameter set is the default `shortint` parameter set that you can also use through the `tfhe::shortint::prelude::DEFAULT_PARAMETERS` constant.

```rust
use tfhe::shortint::prelude::*;

fn main() {
    // We generate a set of client/server keys, using the default parameters:
   let (client_key, server_key) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

    let msg1 = 3;
    let msg2 = 2;

    // We use the client key to encrypt two messages:
    let ct_1 = client_key.encrypt(msg1);
    let ct_2 = client_key.encrypt(msg2);
}
```

## Impact of parameters on the operations

As shown [here](../../getting_started/benchmarks.md), the choice of the parameter set impacts the operations available and their efficiency.

### Generic bi-variate functions.

The computations of bi-variate functions is based on a trick: _concatenating_ two ciphertexts into one. Where the carry buffer is not at least as large as the message buffer, this trick no longer works. In this case, many bi-variate operations, such as comparisons, cannot be correctly computed. The only exception concerns multiplication.

### Multiplication.

In the case of multiplication, two algorithms are implemented: the first one relies on the bi-variate function trick, where the other one is based on the [quarter square method](https://en.wikipedia.org/wiki/Multiplication\_algorithm#Quarter\_square\_multiplication). To correctly compute a multiplication, the only requirement is to have at least one bit of carry (i.e., using parameter sets PARAM\_MESSAGE\_X\_CARRY\_Y with Y>=1). This method is slower than using the other one. Using the `smart` version of the multiplication automatically chooses which algorithm is used depending on the chosen parameters.

## User-defined parameter sets

It is possible to define new parameter sets. To do so, it is sufficient to use the function `unsecure_parameters()` or to manually fill the `ClassicPBSParameters` structure fields.

For instance:

```rust
use tfhe::shortint::prelude::*;

fn main() {
    let param = unsafe {
        ClassicPBSParameters::new(
            LweDimension(656),
            GlweDimension(2),
            PolynomialSize(512),
            StandardDev(0.000034119201269311964),
            StandardDev(0.00000004053919869756513),
            DecompositionBaseLog(8),
            DecompositionLevelCount(2),
            DecompositionBaseLog(3),
            DecompositionLevelCount(4),
            MessageModulus(4),
            CarryModulus(1),
            CiphertextModulus::new_native(),
            EncryptionKeyChoice::Big,
        )
    };
}
```
