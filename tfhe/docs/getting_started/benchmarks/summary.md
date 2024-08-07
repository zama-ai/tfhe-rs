# Benchmarks

This document summarizes the timings of some homomorphic operations over 64-bit encrypted integers, depending on the hardware. More details are given for [the CPU](cpu\_benchmarks.md), [the GPU](gpu\_benchmarks.md), or [zeros-knowledge proofs](zk\_proof\_benchmarks.md).

### Operation time (ms) over FheUint 64

{% embed url="https://docs.google.com/spreadsheets/d/1PZlnBnqax3hfo7xPir3W-et3es_Qx3Y5_CkdoQVjtb0/edit?gid=1430012664#gid=1430012664" fullWidth="true" %}

| Operation over `FheUint64` \ Hardware                  | `CPU`   | `GPU`   |
| ------------------------------------------------------ | ------- | ------- |
| Negation (`-`)                                         | 141 ms  | 52.4 ms |
| Add / Sub (`+`,`-`)                                    | 150 ms  | 52.4 ms |
| Mul (`x`)                                              | 425 ms  | 378 ms  |
| Equal / Not Equal (`eq`, `ne`)                         | 56.0 ms | 19.5 ms |
| Comparisons (`ge`, `gt`, `le`, `lt`)                   | 116 ms  | 40.2 ms |
| Max / Min (`max`,`min`)                                | 159 ms  | 61.4 ms |
| Bitwise operations (`&`, `\|`, `^`)                    | 21.7 ms | 8.26 ms |
| Div / Rem (`/`, `%`)                                   | 10.5 s  | 3.6 s   |
| Left / Right Shifts (`<<`, `>>`)                       | 190 ms  | 119 ms  |
| Left / Right Rotations (`left_rotate`, `right_rotate`) | 188 ms  | 119 ms  |
