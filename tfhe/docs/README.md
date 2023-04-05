# What is TFHE-rs?

📁 [Github](https://github.com/zama-ai/tfhe-rs) | 💛 [Community support](https://zama.ai/community) | 🟨 [Zama Bounty Program](https://github.com/zama-ai/bounty-program)

![](\_static/tfhe-rs-doc-home.png)

TFHE-rs is a pure Rust implementation of TFHE for Boolean and integer arithmetics over encrypted data. It includes a Rust and C API, as well as a client-side WASM API.

TFHE-rs is meant for developers and researchers who want full control over what they can do with TFHE, while not worrying about the low level implementation.

The goal is to have a stable, simple, high-performance, and production-ready library for all the advanced features of TFHE.

## Key cryptographic concepts

The TFHE-rs library implements Zama’s variant of Fully Homomorphic Encryption over the Torus (TFHE). TFHE is based on Learning With Errors (LWE), a well-studied cryptographic primitive believed to be secure even against quantum computers.

In cryptography, a raw value is called a message (also sometimes called a cleartext), while an encoded message is called a plaintext and an encrypted plaintext is called a ciphertext.

The idea of homomorphic encryption is that you can compute on ciphertexts while not knowing messages encrypted within them. A scheme is said to be _fully homomorphic_, meaning any program can be evaluated with it, if at least two of the following operations are supported ($$x$$is a plaintext and $$E[x]$$ is the corresponding ciphertext):

* homomorphic univariate function evaluation: $$f(E[x]) = E[f(x)]$$
* homomorphic addition: $$E[x] + E[y] = E[x + y]$$
* homomorphic multiplication: $$E[x] * E[y] = E[x * y]$$

Zama's variant of TFHE is fully homomorphic and deals with fixed-precision numbers as messages. It implements all needed homomorphic operations, such as addition and function evaluation via **Programmable Bootstrapping**. You can read more about Zama's TFHE variant in the [preliminary whitepaper](https://whitepaper.zama.ai/).

Using FHE in a Rust program with TFHE-rs consists in:

* generating a client key and a server key using secure parameters:
  * a client key encrypts/decrypts data and must be kept secret
  * a server key is used to perform operations on encrypted data and could be public (also called an evaluation key)
* encrypting plaintexts using the client key to produce ciphertexts
* operating homomorphically on ciphertexts with the server key
* decrypting the resulting ciphertexts into plaintexts using the client key

If you would like to know more about the problems that FHE solves, we suggest you review our [6 minute introduction to homomorphic encryption](https://6min.zama.ai/).
