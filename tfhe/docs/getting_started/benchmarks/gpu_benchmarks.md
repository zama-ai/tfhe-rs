# GPU Benchmarks

This document details the GPU performance benchmarks of homomorphic operations using **TFHE-rs**.

All GPU benchmarks presented here were obtained on H100 GPUs, and rely on the multithreaded PBS algorithm. The cryptographic parameters `PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS` were used.

## 1xH100
Below come the results for the execution on a single H100.
The following table shows the performance when the inputs of the benchmarked operation are encrypted:

{% embed url="https://docs.google.com/spreadsheets/d/1dhNYXm7oY0l2qjX3dNpSZKjIBJElkEZtPDIWHZ4FA_A/edit?usp=sharing" %}

The following table shows the performance when the left input of the benchmarked operation is encrypted and the other is a clear scalar of the same size:

{% embed url="https://docs.google.com/spreadsheets/d/1wtnFnOwHrSOvfTWluUEaDoTULyveseVl1ZsYo3AOFKk/edit?usp=sharing" %}

## 2xH100

Below come the results for the execution on two H100's.
The following table shows the performance when the inputs of the benchmarked operation are encrypted:

{% embed url="https://docs.google.com/spreadsheets/d/1_2AUeu3ua8_PXxMfeJCh-pp6b9e529PGVEYUuZRAThg/edit?usp=sharing" %}


The following table shows the performance when the left input of the benchmarked operation is encrypted and the other is a clear scalar of the same size:

{% embed url="https://docs.google.com/spreadsheets/d/1nLPt_m1MbkSdhMop0iKDnSN_c605l_JdMpK5JC90N_Q/edit?usp=sharing" %}

## Programmable bootstrapping

The next table shows the execution time of a keyswitch followed by a programmable bootstrapping depending on the precision of the input message. The associated parameter set is given.

{% embed url="https://docs.google.com/spreadsheets/d/1UrjB6MdwMmp6SL8nHx1uB4TKieT1OTei-hoSN5j-UzI/edit?gid=398722698#gid=398722698" %}
