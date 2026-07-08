# Benchmarks over CPU

This document details the CPU performance benchmarks of homomorphic operations using **TFHE-rs**.

By their nature, homomorphic operations run slower than their cleartext equivalents.

{% hint style="info" %}
All CPU benchmarks were launched on an `AWS hpc8a.96xlarge` instance equipped with two 96-core `AMD EPYC 9R45 CPU @ 2.30GHz` and 768GB of RAM.
{% endhint %}

{% hint style="info" %}
The numbers reported below were obtained with transparent huge pages disabled. To reproduce them, see [System tuning](../../../configuration/system-tuning.md).
{% endhint %}

* [Integer operations](cpu-integer-operations.md)
* [ERC7984](cpu-erc7984.md)
* [KVStore](cpu-kvstore.md)
* [Programmable Bootstrapping](cpu-programmable-bootstrapping.md)
