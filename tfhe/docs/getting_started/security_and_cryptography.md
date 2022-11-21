# Security and Cryptography

## TFHE

TFHE-rs is a cryptographic library dedicated to Fully Homomorphic Encryption. As its name suggests, it is based on the TFHE scheme.

It is interesting to understand some basics about TFHE in order to comprehend where the limitations are coming from, both in terms of precision (number of bits used to represent the plaintext values) and execution time (why TFHE operations are slower than native operations).

## LWE ciphertexts

Although there are many kinds of ciphertexts in TFHE, all the encrypted values in TFHE-rs are mainly stored as LWE ciphertexts.

The security of TFHE relies on the LWE problem, which stands for Learning With Errors. The problem is believed to be secure against quantum attacks.

An LWE Ciphertext is a collection of 32-bit or 64-bit unsigned integers. Before encrypting a message in an LWE ciphertext, one must first encode it as a plaintext. This is done by shifting the message to the most significant bits of the unsigned integer type used.

Then, a little random value called noise is added to the least significant bits. This noise (also called error for Learning With Errors) is crucial to the security of the ciphertext.

$$plaintext = (\Delta * m) + e$$

![](../\_static/lwe.png)

To go from a **plaintext** to a **ciphertext,** one must encrypt the plaintext using a secret key.

An LWE secret key is a list of `n` random integers: $$S = (s_0, ..., s_n)$$. $$n$$ is called the $$LweDimension$$

A LWE ciphertext, is composed of two parts:

* The mask $$(a_0, ..., a_{n-1})$$
* The body $$b$$

The mask of a _fresh_ ciphertext (one that is the result of an encryption and not an operation, such as ciphertext addition) is a list of `n` uniformly random values.

The body is computed as follows:

$$b = (\sum_{i = 0}^{n-1}{a_i * s_i}) + plaintext$$

Now that the encryption scheme is defined, to illustrate why it is slower to compute over encrypted data, let us show the example of the addition between ciphertexts.

To add two ciphertexts, we must add their $mask$ and $body$, as is done below.

$$
ct_0 = (a_{0}, ..., a_{n}, b) \\ ct_1 = (a_{1}^{'}, ..., a_{n}^{'}, b^{'}) \\ ct_{2} = ct_0 + ct_1 \\ ct_{2} = (a_{0} + a_{0}^{'}, ..., a_{n} + a_{n}^{'}, b + b^{'})\\ b + b^{'} = (\sum_{i = 0}^{n-1}{a_i * s_i}) + plaintext + (\sum_{i = 0}^{n-1}{a_i^{'} * s_i}) + plaintext^{'}\\ b + b^{'} = (\sum_{i = 0}^{n-1}{(a_i + a_i^{'})* s_i}) + \Delta m + \Delta m^{'} + e + e^{'}\\
$$

To add ciphertexts, it is sufficient to add their masks and bodies. Instead of just adding 2 integers, one needs to add $$n + 1$$ elements. The addition is an intuitive example to show the slowdown of FHE computation compared to plaintext computation, but other operations are far more expensive (e.g., the computation of a lookup table using the Programmable Bootstrapping).

## Understanding noise and padding

In FHE, there are two types of operations that can be applied to ciphertexts:

* **leveled operations**, which increase the noise in the ciphertext
* **bootstrapped operations**, which reduce the noise in the ciphertext

In FHE, the noise must be tracked and managed in order to guarantee the correctness of the computation.

Bootstrapping operations are used across the computation to decrease the noise in the ciphertexts, preventing it from tampering the message. The rest of the operations are called leveled because they do not need bootstrapping operations and, thus, are usually really fast.

The following sections explain the concept of noise and padding in ciphertexts.

### Noise.

For it to be secure, LWE requires random noise to be added to the message at encryption time.

In TFHE, this random noise is drawn from a Centered Normal Distribution parameterized by a standard deviation. This standard deviation is a security parameter. With all other security parameters set, the larger the standard deviation is, the more secure the encryption is.

In `TFHE-rs`, the noise is encoded in the least significant bits of the plaintexts. Each leveled computation will increase the noise. Thus, if too many computations are performed, the noise will eventually overflow onto the significant data bits of the message and lead to an incorrect result.

The figure below illustrates this problem in case of an addition, where an extra bit of noise is incurred as a result.

![Noise overtaking the plaintexts after homomorphic addition. Most significant bits are on the left.](../\_static/fig7.png)

TFHE-rs offers the ability to automatically manage noise by performing bootstrapping operations to reset the noise when needed.

### Padding.

Since encoded values have a fixed precision, operating on them can sometimes produce results that are outside the original interval. To avoid losing precision or wrapping around the interval, TFHE-rs uses additional bits by defining bits of **padding** on the most significant bits.

As an example, consider adding two ciphertexts. Adding two values could end up outside the range of either ciphertext, and thus necessitate a carry, which would then be carried onto the first padding bit. In the figure below, each plaintext over 32 bits has one bit of padding on its left (i.e., the most significant bit). After the addition, the padding bit is no longer available, as it has been used in order for the carry. This is referred to as **consuming** bits of padding. Since no padding is left, there is no guarantee that further additions would yield correct results.

![](../\_static/fig6.png)

If you would like to know more about TFHE, you can find more information in our [TFHE Deep Dive](https://www.zama.ai/post/tfhe-deep-dive-part-1).

### Security.

By default, the cryptographic parameters provided by `TFHE-rs` ensure at least 128 bits of security. The security has been evaluated using the latest versions of the Lattice Estimator ([repository](https://github.com/malb/lattice-estimator)) with `red_cost_model = reduction.RC.BDGL16`.

For all sets of parameters, the error probability when computing a univariate function over one ciphertext is $$2^{-40}$$. Note that univariate functions might be performed when arithmetic functions are computed (for instance, the multiplication of two ciphertexts).

### Public key encryption.

In public key encryption, the public key contains a given number of ciphertexts all encrypting the value 0. By setting the number of encryptions of 0 in the public key at $$m = \lceil (n+1) \log(q) \rceil + \lambda$$, where $$n$$ is the LWE dimension, $$q$$ is the ciphertext modulus, and $$\lambda$$ is the number of security bits. In a nutshell, this construction is secure due to the leftover hash lemma, which is essentially related to the impossibility of breaking the underlying multiple subset sum problem. By using this formula, this guarantees both a high-density subset sum and an exponentially large number of possible associated random vectors per LWE sample (a,b).
