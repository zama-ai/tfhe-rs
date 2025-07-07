# Benchmarks over CPU

This document details the CPU performance benchmarks of homomorphic operations using **TFHE-rs**.

By their nature, homomorphic operations run slower than their cleartext equivalents.

{% hint style="info" %}
All CPU benchmarks were launched on an `AWS hpc7a.96xlarge` instance equipped with a 96-core `AMD EPYC 9R14 CPU @ 2.60GHz` and 740GB of RAM.
{% endhint %}

* [Integer operations](cpu-integer-operations.md)
* [Programmable Bootstrapping](cpu-programmable-bootstrapping.md)
