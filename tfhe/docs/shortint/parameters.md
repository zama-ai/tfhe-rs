# Cryptographic Parameters

All parameter sets provide at least 128-bits of security according to the [Lattice-Estimator](https://github.com/malb/lattice-estimator), with an error probability equal to $$2^{-40}$$ when computing a programmable bootstrapping. This error probability is due to the randomness added at each encryption (see [here](../getting\_started/security\_and\_cryptography.md) for more details about the encryption process).

## Parameters and message precision

`shortint` comes with sets of parameters that permit the use of the library functionalities securely and efficiently. Each parameter set is associated to the message and carry precisions. Thus, each key pair is entangled to precision.

The user is allowed to choose which set of parameters to use when creating the pair of keys.

The difference between the parameter sets is the total amount of space dedicated to the plaintext and how it is split between the message buffer and the carry buffer. The syntax chosen for the name of a parameter is: `PARAM_MESSAGE_{number of message bits}_CARRY_{number of carry bits}`. For example, the set of parameters for a message buffer of 5 bits and a carry buffer of 2 bits is `PARAM_MESSAGE_5_CARRY_2`.

In what follows, there is an example where keys are generated to have messages encoded over 3 bits i.e., computations are done modulus $$2^3 = 8$$), with 3 bits of carry.

```rust
use tfhe::shortint::prelude::*;

fn main() {
    // We generate a set of client/server keys, using the default parameters:
   let (client_key, server_key) = gen_keys(PARAM_MESSAGE_2_CARRY_2);

    let msg1 = 3;
    let msg2 = 7;

    // We use the client key to encrypt two messages:
    let ct_1 = client_key.encrypt(msg1);
    let ct_2 = client_key.encrypt(msg2);
}
```

## Impact of parameters on the operations

As shown [here](../getting\_started/benchmarks.md), the choice of the parameter set impacts the operations available and their efficiency.

### Generic bi-variate functions.

The computations of bi-variate functions is based on a trick, _concatenating_ two ciphertexts into one. In the case where the carry buffer is not at least as large as the message one, this trick no longer works. Then, many bi-variate operations, such as comparisons cannot be correctly computed. The only exception concerns the multiplication.

### Multiplication.

In the case of the multiplication, two algorithms are implemented: the first one relies on the bi-variate function trick, where the other one is based on the [quarter square method](https://en.wikipedia.org/wiki/Multiplication\_algorithm#Quarter\_square\_multiplication). In order to correctly compute a multiplication, the only requirement is to have at least one bit of carry (i.e., using parameter sets PARAM\_MESSAGE\_X\_CARRY\_Y with Y>=1). This method is, in general, slower than using the other one. Note that using the `smart` version of the multiplication automatically chooses which algorithm is used depending on the chosen parameters.

## User-defined parameter sets

Beyond the predefined parameter sets, it is possible to define new parameter sets. To do so, it is sufficient to use the function `unsecure_parameters()` or to manually fill the `Parameter` structure fields.

For instance:

```rust
use tfhe::shortint::prelude::*;

fn main() {
    let param = unsafe {
        Parameters::new(
            LweDimension(656),
            GlweDimension(2),
            PolynomialSize(512),
            StandardDev(0.000034119201269311964),
            StandardDev(0.00000004053919869756513),
            DecompositionBaseLog(8),
            DecompositionLevelCount(2),
            DecompositionBaseLog(3),
            DecompositionLevelCount(4),
            StandardDev(0.00000000037411618952047216),
            DecompositionBaseLog(15),
            DecompositionLevelCount(1),
            DecompositionLevelCount(0),
            DecompositionBaseLog(0),
            MessageModulus(4),
            CarryModulus(1),
        )
    };
}
```
