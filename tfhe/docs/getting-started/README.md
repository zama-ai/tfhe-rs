# What is TFHE-rs?

![](../.gitbook/assets/doc-header-tfhe-rs.png)

**TFHE-rs** is a pure Rust implementation of Fully Homomorphic Encryption over the Torus (TFHE) to perform Boolean and integer arithmetic on encrypted data.

**TFHE-rs** implements advanced TFHE features, empowering developers and researchers with fine-grained control over TFHE so that they can focus on high-level functionality without delving into low-level implementation.

**TFHE-rs** includes:

* **Rust API**: the primary API for working with **TFHE-rs** in Rust projects.
* **C API**: for developers who prefer to use C.
* **Client-side WASM API**: to integrate **TFHE-rs** functionalities into WebAssembly applications.

## Key cryptographic concepts

TFHE is a Fully Homomorphic Encryption (FHE) scheme based on Learning With Errors (LWE), which is a secure cryptographic primitive against even quantum computers. The **TFHE-rs** library implements Zama’s variant of TFHE.

#### Homomorphic Encryption Basics

The basic elements of cryptography:

* **Message (or Cleartext):** raw values before encryption.
* **Plaintext:** encoded messages.
* **Ciphertext**: encrypted messages.

FHE allows to compute on ciphertexts without revealing the content of the messages. A scheme is fully homomorphic if it supports at least two of the following operations when evaluating any programs. ($$x$$ is a plaintext and $$E[x]$$ is the corresponding ciphertext):

* **Homomorphic univariate function evaluation:** $$f(E[x]) = E[f(x)]$$
* **Homomorphic addition:** $$E[x] + E[y] = E[x + y]$$
* **Homomorphic multiplication:** $$E[x] * E[y] = E[x * y]$$

## Zama's variant of TFHE

Zama's variant of TFHE is a fully homomorphic scheme that takes fixed-precision numbers as messages. It implements all homomorphic operations needed, such as addition and function evaluation via Programmable Bootstrapping.

Refer to the [preliminary whitepaper](https://whitepaper.zama.org/) for more details.

Using **TFHE-rs** in Rust includes the following steps:

1. **Key generation**: generate a pair of keys using secure parameters.
   * **Client key**: used for encryption and decryption of data. This key must be kept secret.
   * **Server key (or Evaluation key)**: used for performing operations on encrypted data. This key could be public.
2. **Encryption**: encrypt plaintexts using the client key to produce ciphertexts.
3. **Homomorphic operation**: perform operations on ciphertexts using the server key.
4. **Decryption**: decrypt the resulting ciphertexts back to plaintexts using the client key.

To understand more about FHE applications, see the [6-minute introduction to homomorphic encryption](https://6min.zama.org/).
