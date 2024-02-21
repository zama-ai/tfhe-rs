# Cryptographic Parameters

## Default parameters

The TFHE cryptographic scheme relies on a variant of [Regev cryptosystem](https://cims.nyu.edu/\~regev/papers/lwesurvey.pdf) and is based on a problem so difficult that it is even post-quantum resistant.

Some cryptographic parameters will require tuning to ensure both the correctness of the result and the security of the computation.

To make it simpler, **we've provided two sets of parameters**, which ensure correct computations for a certain probability with the standard security of 128 bits. There exists an error probability due to the probabilistic nature of the encryption, which requires adding randomness (noise) following a Gaussian distribution. If this noise is too large, the decryption will not give a correct result. There is a trade-off between efficiency and correctness: generally, using a less efficient parameter set (in terms of computation time) leads to a smaller risk of having an error during homomorphic evaluation.

In the two proposed sets of parameters, the only difference lies in this error probability. The default parameter set ensures an error probability of at most $$2^{-40}$$ when computing a programmable bootstrapping (i.e., any gates but the `not`). The other one is closer to the error probability claimed in the original [TFHE paper](https://eprint.iacr.org/2018/421), namely $$2^{-165}$$, but it is up-to-date regarding security requirements.

The following array summarizes this:

|     Parameter set     | Error probability |
| :-------------------: | :---------------: |
|  DEFAULT\_PARAMETERS  |    $$2^{-40}$$    |
| TFHE\_LIB\_PARAMETERS |    $$2^{-165}$$   |

## User-defined parameters

You can also create your own set of parameters. This is an `unsafe` operation as failing to properly fix the parameters will result in an incorrect and/or insecure computation:

```rust
use tfhe::boolean::prelude::*;

fn main() {
// WARNING: might be insecure and/or incorrect
// You can create your own set of parameters
    let parameters = unsafe {
        BooleanParameters::new(
            LweDimension(586),
            GlweDimension(2),
            PolynomialSize(512),
            StandardDev(0.00008976167396834998),
            StandardDev(0.00000002989040792967434),
            DecompositionBaseLog(8),
            DecompositionLevelCount(2),
            DecompositionBaseLog(2),
            DecompositionLevelCount(5),
            EncryptionKeyChoice::Small,
        )
    };
}
```
