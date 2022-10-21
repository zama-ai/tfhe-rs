# Probability of Error


The security of homomorphic encryption schemes is based on a hard problem, requiring to add noise
to ciphertexts in order to meet a fixed security level.
Homomorphic computations are therefore noisy by design.

A too big amount of noise might render an encrypted message no longer decryptable.
Then, it is really important to caliber the choice of the parameters depending on the error
probability they provide.

There is a trade-off between efficiency and correctness: generally, using a less efficient
parameter set (in
terms of computation time) leads to a smaller risk of having an error during homomorphic evaluation.

We propose two sets of parameters, both achieving 128 bits of security,  which offer the
possibility to make the more convenient choice according to the use-case.


|    Parameter set    | Time per binary gate | Error probability |
|:-------------------:|:--------------------:|:-----------------:|
|  DEFAULT_PARAMETERS |        11.3 ms       |    $ 2^{-25} $    |
| TFHE_LIB_PARAMETERS |        18.0 ms       |    $ 2^{-165} $   |


The previous table gives the error probability for a boolean gate according to the parameter set.

The measured time for a boolean gate computation was obtained on a regular laptop with a 2,6 GHz
6-core Intel Core i7 processor equipped with AVX2 and on a single thread.
