# Cryptographic parameters

The TFHE cryptographic scheme relies on a variant of [Regev
cryptosystem](https://cims.nyu.edu/~regev/papers/lwesurvey.pdf),
and is based on a problem so hard to solve, that is even post-quantum resistant.

In practice, you need to tune some cryptographic parameters, in order to ensure the correctness
of the result, and the security of the computation.

To make it simpler, **we provide two sets of parameters**, which ensure correct computations for a
certain probability with the standard security of 128 bits. 
There exists an error probability due the probabilistic nature of the encryption, which requires 
adding randomness (call noise) following a Gaussian distribution. If this noise is too large, 
the decryption will not give a correct result. There is a trade-off between efficiency and correctness: generally, using a less efficient
parameter set (in terms of computation time) leads to a smaller risk of having an error during homomorphic evaluation.

In the two proposed sets of parameters, the only difference lies into this probability error. 
The default parameter set ensures a probability error of at most 2^(-40) when computing a 
programmable bootstrapping (i.e., any gates but the `not`). The other one is closer to what is 
claimed into the original [TFHE paper](https://eprint.iacr.org/2018/421), namely 2^(-165).

The following array summarizes this:

|    Parameter set    | Error probability |
|:-------------------:|:-----------------:|
|  DEFAULT_PARAMETERS |    $ 2^{-40} $    |
| TFHE_LIB_PARAMETERS |    $ 2^{-165} $   |


# Public key parameters
By setting the number of encryptions of 0 in the public key at m = ceil( (n+1) log_q ) + lambda,
where n is the LWE dimension, q is the ciphertext modulus and lambda is the number of security bits.
In a nutshell, this construction is secure due to the left-over-hash lemma, which is essentially
related to the impossibility of breaking the underlying multiple subset sum problem.
By using this formula, this
guarantees both a high density subset sum and an
exponentially large number of possible associated random vectors per LWE sample (a,b)"



# User-defined parameters 


Note that if you desire, you can also create your own set of parameters.
This is an `unsafe` operation as failing to properly fix the parameters will potentially result
with an incorrect and/or insecure computation:

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
        )
    };
}
```


