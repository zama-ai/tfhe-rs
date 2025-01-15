# Security and cryptography

This document introduces the cryptographic concepts of the scheme of Fully Homomorphic Encryption over the Torus (TFHE)  and the security considerations of **TFHE-rs.**

## TFHE

**TFHE-rs** is a cryptographic library that implements Fully Homomorphic Encryption using the TFHE scheme. You should understand the basics of TFHE to consider its limitations, such as:

* **The precision**: TFHE has limitations on the number of bits used to represent plaintext values.
* **The execution time**: TFHE operations are slower than native operations due to their complexity.

## LWE ciphertexts

TFHE-rs primarily utilizes Learning With Errors (LWE) ciphertexts. The LWE problem forms the basis of TFHE's security and is considered resistant to quantum attacks.

An LWE Ciphertext is a collection of 32-bit or 64-bit unsigned integers. Before encrypting a message in an LWE ciphertext, you first need to encode it as a plaintext by shifting the message to the most significant bits of the unsigned integer type used.

Then, you add a small random value called noise to the least significant bits. This noise is crucial in ensuring the security of the ciphertext.

$$plaintext = (\Delta * m) + e$$

$$m \in \mathbb{Z}_p$$

![](../\_static/lwe.png)

To get a **ciphertext** from a **plaintext,** you must encrypt the plaintext using a secret key.

An LWE secret key is a list of `n` random integers: $$S = (s_0, ..., s_{n-1})$$. $$n$$ is called the $$LweDimension$$

An LWE ciphertext is composed of two parts:

* The mask $$(a_0, ..., a_{n-1})$$
* The body $$b$$

The mask of a fresh ciphertext (the result of an encryption, and not the result of operations such as ciphertext addition) is a list of `n` uniformly random values.

The body is computed as follows:

$$b = (\sum_{i = 0}^{n-1}{a_i * s_i}) + plaintext$$

Now that the encryption scheme is defined, let's review the example of the addition between ciphertexts to illustrate why it is slower to compute over encrypted data.

To add two ciphertexts, we must add their $$mask$$ and $$body$$:

$$
ct_0 = (a_{0}, ..., a_{n-1}, b) \\ ct_1 = (a_{0}^{\prime}, ..., a_{n-1}^{\prime}, b^{\prime}) \\ ct_{2} = ct_0 + ct_1 \\ ct_{2} = (a_{0} + a_{0}^{\prime}, ..., a_{n-1} + a_{n-1}^{\prime}, b + b^{\prime})\\ b + b^{\prime} = (\sum_{i = 0}^{n-1}{a_i * s_i}) + plaintext + (\sum_{i = 0}^{n-1}{a_i^{\prime} * s_i}) + plaintext^{\prime}\\ b + b^{\prime} = (\sum_{i = 0}^{n-1}{(a_i + a_i^{\prime})* s_i}) + \Delta m + \Delta m^{\prime} + e + e^{\prime}\\
$$

To add ciphertexts, it is necessary to add both their masks and bodies. The operation involves adding $$n + 1$$ elements, rather than just adding two integers. This is an intuitive example to show how FHE computation is slower compared to plaintext computation. However, other operations are far more expensive (for example, the computation of a lookup table using Programmable Bootstrapping).

## Programmable Bootstrapping, noise management, and carry bits

In FHE, two types of operations can be applied to ciphertexts:

* **Leveled operations**, which increase the noise in the ciphertext
* **Bootstrapped operations**, which reduce the noise in the ciphertext

Noise is critical in FHE because it can tamper with the message if not tracked and managed properly. Bootstrapping operations decrease noise within the ciphertexts and guarantee the correctness of computation. The rest of the operations do not need bootstrapping operations, thus they are called leveled operations and are usually very fast as a result.

The following sections explain the concept of noise and padding in ciphertexts.

### Noise

To ensure security, LWE requires random noise to be added to the message during encryption.

TFHE scheme draws this random noise either from:
- A Centered Normal Distribution with a standard deviation parameter. The choice of standard deviation impacts the security level: increasing the standard deviation enhances security while keeping other factors constant.
- A Tweaked Uniform (TUniform) Distribution with a bound parameter $$2^b$$ defined as follows: any value in the interval $$(−2^b, ... , 2^b)$$ is selected with probability $$1/2^{b+1}$$, with the two end points $$−2^b$$ and $$2^b$$ being selected with probability $$1/2^{b+2}$$. The main advantage of this distribution is to be bounded, whereas the usual Central Normal Distribution one is not. In some practical cases, this can simplify the use of homomorphic computation. The choice of the bound impacts the security level: increasing the bound enhances security while keeping other factors constant.

**TFHE-rs** encodes the noise in the least significant bits of each plaintext. Each leveled computation increases the value of the noise. If too many computations are performed, the noise will eventually overflow into the message bits and lead to an incorrect result.

The following figure illustrates how the extra bit of noise is incurred during an addition operation.

![Noise overtaking the plaintexts after homomorphic addition. Most significant bits are on the left.](../\_static/overflow.png)

**TFHE-rs** enables automatic noise management by performing bootstrapping operations to reset the noise.

### Programmable BootStrapping (PBS)

The bootstrapping of TFHE is programmable. This allows any function to be homomorphically computed over an encrypted input, while also reducing the noise. These functions are represented by look-up tables.

In general, the computation of a PBS is preceded or followed by a keyswitch, an operation to change the encryption key. The output ciphertext is then encrypted with the same key as the input one. To do this, two (public) evaluation keys are required: a bootstrapping key and a keyswitching key.

These operations are quite complex to describe in short, you can find more details about these operations (or about TFHE in general) in the [TFHE Deep Dive](../explanations/tfhe-deep-dive.md).

### Carry

Since encoded values have a fixed precision, operating on them can produce results that are outside of the original interval. To avoid losing precision or wrapping around the interval, **TFHE-rs** uses additional bits by defining bits of **padding** on the most significant bits.

For example, when adding two ciphertexts, the sum could exceed the range of either ciphertext, and thus necessitate a carry that would then be transferred onto the first padding bit. In the following figure, each plaintext over 32 bits has one bit of padding on its left (the most significant bit). After the addition, the padding bit gets consumed to accommodate the carry. We refer to this process as **consuming** bits of padding. Without any padding-left, further additions may not produce accurate results.

![](../\_static/carry.png)

## Security

By default, the cryptographic parameters provided by **TFHE-rs** ensure at least 128 bits of security. The security has been evaluated using the latest versions of the Lattice Estimator ([repository](https://github.com/malb/lattice-estimator)) with `red_cost_model = reduction.RC.BDGL16`.

The default parameters for the **TFHE-rs** library are chosen considering the IND-CPA security model, and are selected with a bootstrapping failure probability fixed at p\_error = $$2^{-64}$$. In particular, it is assumed that the results of decrypted computations are not shared by the secret key owner with any third parties, as such an action can lead to leakage of the secret encryption key. If you are designing an application where decryptions must be shared, you will need to craft custom encryption parameters which are chosen in consideration of the IND-CPA^D security model \[1].

\[1][ Li, Baiyu, et al. "Securing approximate homomorphic encryption using differential privacy." Annual International Cryptology Conference. Cham: Springer Nature Switzerland, 2022.](https://eprint.iacr.org/2022/816.pdf)

## Classical public key encryption.

In classical public key encryption, the public key contains a given number of ciphertexts all encrypting the value 0. By setting the number of encryptions to 0 in the public key at $$m = \lceil (n+1) \log(q) \rceil + \lambda$$, where $$n$$ is the LWE dimension, $$q$$ is the ciphertext modulus, and $$\lambda$$ is the number of security bits. This construction is secure due to the leftover hash lemma, which relates to the impossibility of breaking the underlying multiple subset sum problem. This guarantees both a high-density subset sum and an exponentially large number of possible associated random vectors per LWE sample $$(a,b)$$.
