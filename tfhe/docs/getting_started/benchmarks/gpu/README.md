# Benchmarks over GPU

This document details the GPU performance benchmarks of homomorphic operations using **TFHE-rs**.

By their nature, homomorphic operations run slower than their cleartext equivalents.

{% hint style="info" %}
All CPU benchmarks were launched on H100 GPUs, and rely on the multithreaded PBS algorithm.
{% endhint %}

* [Integer operations](gpu_integer_operations.md)
* [Programmable Bootstrapping](gpu_programmable_bootstrapping.md)
