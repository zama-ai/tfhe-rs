# What is TFHE.rs?

<mark style="background-color:yellow;">⭐️</mark> [<mark style="background-color:yellow;">Star the repo on Github</mark>](https://github.com/zama-ai/tfhe-rs) <mark style="background-color:yellow;">| 🗣</mark> [<mark style="background-color:yellow;">Community support forum</mark> ](https://community.zama.ai)<mark style="background-color:yellow;">| 📁</mark> [<mark style="background-color:yellow;">Contribute to the project</mark>](https://docs.zama.ai/tfhe-rs/developers/contributing)<mark style="background-color:yellow;"></mark>

![](_static/docs\_home.jpg)

`TFHE.rs` is a Rust crate meant to provide a complete and easy-to-use library to enable building applications using Fully Homomorphic Encryption (FHE).
FHE is a powerful cryptographic tool, which allows computation to be performed directly on encrypted data without needing to decrypt it first. `TFHE.rs` contains functionalities related to the vanilla [TFHE
scheme](https://eprint.iacr.org/2018/421.pdf). This crate is split in two parts: one is dedicated to the computations over booleans whereas the other one focus on short integers (from 2 to 8 bits).

Differently from [concrete](https://www.zama.ai/concrete-framework), this library offers lower level APIs, a C API for all functions and a WASM API related to client-side functionalities. TFHE.rs basically encompasses the [tfhelib](https://tfhe.github.io/tfhe/) features, along with the possibility to easily 
work on unsigned short integers. 

### Key Cryptographic concepts

TFHE.rs library implements Zama’s variant of Fully Homomorphic Encryption over the Torus (TFHE). TFHE is based on Learning With Errors (LWE), a well studied cryptographic primitive believed to be secure even against quantum computers.

In cryptography, a raw value is called a message (also sometimes called a cleartext), an encoded message is called a plaintext and an encrypted plaintext is called a ciphertext.

The idea of homomorphic encryption is that you can compute on ciphertexts while not knowing messages encrypted in them. A scheme is said to be _fully homomorphic_, meaning any program can be evaluated with it, if at least two of the following operations are supported \($$x$$is a plaintext and $$E[x]$$ is the
corresponding ciphertext\):

* homomorphic univariate function evaluation: $$f(E[x]) = E[f(x)]$$
* homomorphic addition: $$E[x] + E[y] = E[x + y]$$
* homomorphic multiplication: $$E[x] * E[y] = E[x * y]$$

Zama's variant of TFHE is fully homomorphic and deals with fixed-precision numbers as messages. It implements all needed homomorphic operations, such as addition and function evaluation via **Programmable Bootstrapping**. You can read more about Zama's TFHE variant in the [preliminary whitepaper](https://whitepaper.zama.ai/).

Using FHE in a Rust program with TFHE.rs consists in:

* generating a client key and a server key using secure parameters:
    * client key encrypts/decrypts data and must be kept secret
    * server key is used to perform operations on encrypted data and could be
      public (also called evaluation key)
* encrypting plaintexts using the client key to produce ciphertexts
* operating homomorphically on ciphertexts with the server key
* decrypting the resulting ciphertexts into plaintexts using the client key

If you would like to know more about the problems that FHE solves, we suggest you review our [6 minute introduction to homomorphic encryption](https://6min.zama.ai/).
