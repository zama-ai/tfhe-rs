# GPU Benchmarks

This document details the GPU performance benchmarks of homomorphic operations using **TFHE-rs**.

All GPU benchmarks presented here were obtained on H100 GPUs, and rely on the multithreaded PBS algorithm. The cryptographic parameters `PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS` were used.

## 1xH100
Below come the results for the execution on a single H100.
The following table shows the performance when the inputs of the benchmarked operation are encrypted:

{% embed url="https://docs.google.com/spreadsheets/d/1xGWykMa8fZ7RWUjkCl-52FJ-BNge8cB-5CSHrVZ6XRo/edit?usp=sharing" %}

The following table shows the performance when the left input of the benchmarked operation is encrypted and the other is a clear scalar of the same size:

{% embed url="https://docs.google.com/spreadsheets/d/1MZfE9c-cQw3yAP55tu0i8uLl4lTAiH9zW3gRFp0ve7s/edit?usp=sharing" %}

## 2xH100

Below come the results for the execution on two H100's.
The following table shows the performance when the inputs of the benchmarked operation are encrypted:

{% embed url="https://docs.google.com/spreadsheets/d/1bcL0wgFk-cfR4asGSCWDFt7JaqDYJT-l4pH58A-yBkc/edit?usp=sharing" %}


The following table shows the performance when the left input of the benchmarked operation is encrypted and the other is a clear scalar of the same size:

{% embed url="https://docs.google.com/spreadsheets/d/1_8VIoStixns22lQq_RBSjVm-0iFHjJpntQTrvEHZpSg/edit?usp=sharing" %}

## Programmable bootstrapping

The next table shows the execution time of a keyswitch followed by a programmable bootstrapping depending on the precision of the input message. The associated parameter set is given.

Note that these benchmarks use Gaussian parameters.

{% embed url="https://docs.google.com/spreadsheets/d/1KhElQ7sIsShUSVQw5bKFoP-x5BgMaWh1pZtrVAdC3T4/edit?usp=sharing" %}
