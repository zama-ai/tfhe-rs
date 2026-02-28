# TFHE deep dive

TFHE is a fully homomorphic encryption scheme that enables fast homomorphic operations on booleans, integers and reals.

By enabling both leveled and bootstrapped operations, TFHE can be used for a wide range of usecases, from homomorphic boolean circuits to homomorphic neural networks.

Here are a series of articles that guide you to go deeper into the understanding of the scheme:

* [TFHE Deep Dive - Part I - Ciphertext types](https://www.zama.org/post/tfhe-deep-dive-part-1)
* [TFHE Deep Dive - Part II - Encodings and linear leveled operations](https://www.zama.org/post/tfhe-deep-dive-part-2)
* [TFHE Deep Dive - Part III - Key switching and leveled multiplications](https://www.zama.org/post/tfhe-deep-dive-part-3)
* [TFHE Deep Dive - Part IV - Programmable Bootstrapping](https://www.zama.org/post/tfhe-deep-dive-part-4)

The **TFHE-rs** handbook makes an [in-depth description of TFHE](https://github.com/zama-ai/tfhe-rs-handbook).

The article [Guide to Fully Homomorphic Encryption over the Discretized Torus](https://eprint.iacr.org/2021/1402.pdf) gives more mathematical details about the TFHE scheme.

You can also watch the video record of the original talk by Ilaria Chillotti for FHE.org:

{% embed url="https://youtu.be/npoHSR6-oRw" %}
