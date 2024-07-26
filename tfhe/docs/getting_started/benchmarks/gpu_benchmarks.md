# GPU Benchmarks
This document details the GPU performance benchmarks of homomorphic operations using **TFHE-rs**.

All GPU benchmarks presented here were obtained on H100 GPUs, and rely on the multithreaded PBS algorithm. The cryptographic parameters `PARAM_GPU_MULTI_BIT_MESSAGE_2_CARRY_2_GROUP_3_KS_PBS` were used.

## 1xH100
Below come the results for the execution on a single H100.
The following table shows the performance when the inputs of the benchmarked operation are encrypted:

| Operation \ Size                                       | `FheUint8` | `FheUint16` | `FheUint32` | `FheUint64` | `FheUint128` | `FheUint256` |
|--------------------------------------------------------|------------|-------------|-------------|-------------|--------------|--------------|
| Negation (`-`)                                         | 18.6 ms    | 24.9 ms     | 34.9 ms     | 52.4 ms     | 101 ms       | 197 ms       |
| Add / Sub (`+`,`-`)                                    | 18.7 ms    | 25.0 ms     | 35.0 ms     | 52.4 ms     | 101 ms       | 197 ms       |
| Mul (`x`)                                              | 35.0 ms    | 59.7 ms     | 124 ms      | 378 ms      | 1.31 s       | 5.01 s       |
| Equal / Not Equal (`eq`, `ne`)                         | 10.5 ms    | 11.1 ms     | 17.2 ms     | 19.5 ms     | 27.9 ms      | 45.2 ms      |
| Comparisons  (`ge`, `gt`, `le`, `lt`)                  | 19.8 ms    | 25.0 ms     | 31.3 ms     | 40.2 ms     | 53.2 ms      | 85.2 ms      |
| Max / Min   (`max`,`min`)                              | 30.2 ms    | 37.1 ms     | 46.6 ms     | 61.4 ms     | 91.8 ms      | 154 ms       |
| Bitwise operations (`&`, `\|`, `^`)                    | 4.83 ms    | 5.3 ms      | 6.36 ms     | 8.26 ms     | 15.3 ms      | 25.4 ms      |
| Div / Rem  (`/`, `%`)                                  | 221 ms     | 528 ms      | 1.31 s      | 3.6 s       | 11.0 s       | 40.0 s       |
| Left / Right Shifts (`<<`, `>>`)                       | 30.4 ms    | 41.4 ms     | 60.0 ms     | 119 ms      | 221 ms       | 435 ms       |
| Left / Right Rotations (`left_rotate`, `right_rotate`) | 30.4 ms    | 41.4 ms     | 60.1 ms     | 119 ms      | 221 ms       | 435 ms       |

The following table shows the performance when the left input of the benchmarked operation is encrypted and the other is a clear scalar of the same size:

| Operation \ Size                                       | `FheUint8` | `FheUint16` | `FheUint32` | `FheUint64` | `FheUint128` | `FheUint256` |
|--------------------------------------------------------|------------|-------------|-------------|-------------|--------------|--------------|
| Add / Sub (`+`,`-`)                                    | 19.0 ms    | 25.0 ms     | 35.0 ms     | 52.4 ms     | 101 ms       | 197 ms       |
| Mul (`x`)                                              | 28.1 ms    | 43.9 ms     | 75.4 ms     | 177 ms      | 544 ms       | 1.92 s       |
| Equal / Not Equal (`eq`, `ne`)                         | 11.5 ms    | 11.9 ms     | 12.5 ms     | 18.9 ms     | 21.7 ms      | 30.6 ms      |
| Comparisons  (`ge`, `gt`, `le`, `lt`)                  | 12.5 ms    | 17.4 ms     | 22.7 ms     | 29.9 ms     | 39.1 ms      | 57.2 ms      |
| Max / Min   (`max`,`min`)                              | 22.5 ms    | 28.9 ms     | 37.4 ms     | 50.6 ms     | 77.4 ms      | 126 ms       |
| Bitwise operations (`&`, `\|`, `^`)                    | 4.92 ms    | 5.51 ms     | 6.47 ms     | 8.37 ms     | 15.5 ms      | 25.6 ms      |
| Div (`/`)                                              | 46.8 ms    | 70.0 ms     | 138 ms      | 354 ms      | 1.10 s       | 3.83 s       |
| Rem (`%`)                                              | 90.0 ms    | 140 ms      | 250 ms      | 592 ms      | 1.75 s       | 6.06 s       |
| Left / Right Shifts (`<<`, `>>`)                       | 4.82 ms    | 5.36 ms     | 6.38 ms     | 8.26 ms     | 15.3 ms      | 25.4 ms      |
| Left / Right Rotations (`left_rotate`, `right_rotate`) | 4.81 ms    | 5.36 ms     | 6.30 ms     | 8.19 ms     | 15.3 ms      | 25.3 ms      |

## 2xH100

Below come the results for the execution on two H100's.
The following table shows the performance when the inputs of the benchmarked operation are encrypted:

| Operation \ Size                                       | `FheUint8` | `FheUint16` | `FheUint32` | `FheUint64` | `FheUint128` | `FheUint256` |
| ------------------------------------------------------ | ---------- | ----------- | ----------- | ----------- | ------------ | ------------ |
| Negation (`-`)                                         | 16.1 ms    | 20.3 ms     | 27.7 ms     | 38.2 ms     | 54.7 ms      | 83.0 ms      |
| Add / Sub (`+`,`-`)                                    | 16.1 ms    | 20.4 ms     | 27.8 ms     | 38.3 ms     | 54.9 ms      | 83.2 ms      |
| Mul (`x`)                                              | 31.0 ms    | 49.6 ms     | 92.4 ms     | 267 ms      | 892 ms       | 3.45 s       |
| Equal / Not Equal (`eq`, `ne`)                         | 11.2 ms    | 12.9 ms     | 20.4 ms     | 27.3 ms     | 38.8 ms      | 67.0 ms      |
| Max / Min   (`max`,`min`)                              | 53.4 ms    | 59.3 ms     | 70.4 ms     | 89.6 ms     | 120 ms       | 177 ms       |
| Bitwise operations (`&`, `\|`, `^`)                    | 4.16 ms    | 4.62 ms     | 5.61 ms     | 7.52 ms     | 10.2 ms      | 15.7 ms      |
| Div / Rem  (`/`, `%`)                                  | 299 ms     | 595 ms      | 1.36 s      | 3.12 s      | 7.8 s        | 21.1 s       |
| Left / Right Shifts (`<<`, `>>`)                       | 26.9 ms    | 34.5 ms     | 48.7 ms     | 70.2 ms     | 108 ms       | 220 ms       |
| Left / Right Rotations (`left_rotate`, `right_rotate`) | 26.8 ms    | 34.5 ms     | 48.7 ms     | 70.1 ms     | 108 ms       | 220 ms       |


The following table shows the performance when the left input of the benchmarked operation is encrypted and the other is a clear scalar of the same size:

| Operation \ Size                                       | `FheUint8` | `FheUint16` | `FheUint32` | `FheUint64` | `FheUint128` | `FheUint256` |
| ------------------------------------------------------ |------------|-------------|-------------|-------------|--------------|--------------|
| Add / Sub (`+`,`-`)                                    | 16.4 ms    | 20.5 ms     | 28.0 ms     | 38.4 ms     | 54.9 ms      | 83.1 ms      |
| Mul (`x`)                                              | 25.3 ms    | 36.8 ms     | 62.0 ms     | 130 ms      | 377 ms       | 1.35 s       |
| Equal / Not Equal (`eq`, `ne`)                         | 36.4 ms    | 36.5 ms     | 39.3 ms     | 47.1 ms     | 58.0 ms      | 78.0 ms      |
| Max / Min   (`max`,`min`)                              | 53.6 ms    | 60.8 ms     | 71.9 ms     | 89.4 ms     | 119 ms       | 173 ms       |
| Bitwise operations (`&`, `\|`, `^`)                    | 4.33 ms    | 4.76 ms     | 6.4 ms      | 7.65 ms     | 10.4 ms      | 15.7 ms      |
| Div (`/`)                                              | 40.9 ms    | 59.7 ms     | 109.0 ms    | 248.5 ms    | 806.1 ms     | 2.9 s        |
| Rem (`%`)                                              | 80.6 ms    | 116.1 ms    | 199.9 ms    | 412.9 ms    | 1.2 s        | 4.3 s        |
| Left / Right Shifts (`<<`, `>>`)                       | 4.15 ms    | 4.57 ms     | 6.19 ms     | 7.48 ms     | 10.3 ms      | 15.7 ms      |
| Left / Right Rotations (`left_rotate`, `right_rotate`) | 4.15 ms    | 4.57 ms     | 6.18 ms     | 7.46 ms     | 10.2 ms      | 15.6 ms      |
