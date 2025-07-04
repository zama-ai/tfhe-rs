# GPU operations
This document outlines the GPU operations supported in TFHE-rs. 

The GPU backend includes the following operations for both signed and unsigned encrypted integers:

| name                                                                                                                              | symbol          | `Enc`/`Enc`          | `Enc`/ `Int`               |
|-----------------------------------------------------------------------------------------------------------------------------------|-----------------|----------------------|----------------------------|
| [Neg](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.neg-1)                                                           | `-`             | :heavy\_check\_mark: | N/A                        |
| [Add](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.add-1)                                                           | `+`             | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Sub](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.sub-1)                                                           | `-`             | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Mul](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.mul-1)                                                           | `*`             | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Div](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.div-1)                                                           | `/`             | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Rem](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.rem-1)                                                           | `%`             | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Not](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.not-1)                                                           | `!`             | :heavy\_check\_mark: | N/A                        |
| [BitAnd](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.bitand-1)                                                     | `&`             | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [BitOr](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.bitor-1)                                                       | `\|`            | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [BitXor](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.bitxor-1)                                                     | `^`             | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Shr](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.shr-1)                                                           | `>>`            | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Shl](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.shl-1)                                                           | `<<`            | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Rotate right](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.rotate_right-3)                                         | `rotate_right`  | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Rotate left](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.rotate_left-3)                                           | `rotate_left`   | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Min](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.min-1)                                                           | `min`           | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Max](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.max-1)                                                           | `max`           | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Greater than](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.gt-2)                                                   | `gt`            | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Greater or equal than](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.ge-2)                                          | `ge`            | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Lower than](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.lt-2)                                                     | `lt`            | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Lower or equal than](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.le-2)                                            | `le`            | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Equal](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.eq-2)                                                          | `eq`            | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Not Equal](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.ne-2)                                                      | `ne`            | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| [Cast (into dest type)](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.cast_into)                                     | `cast_into`     | :heavy\_check\_mark: | N/A                        |
| [Cast (from src type)](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.cast_from-2)                                    | `cast_from`     | :heavy\_check\_mark: | N/A                        |
| [Ternary operator](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.select)                                             | `select`        | :heavy\_check\_mark: | :heavy\_multiplication\_x: |
| [Integer logarithm](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.ilog2)                                             | `ilog2`         | :heavy\_check\_mark: | N/A                        |
| [Count trailing/leading ones](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.leading_ones)                            | `leading_zeros` | :heavy\_check\_mark: | N/A                        |
| [Count trailing/leading zeros](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.leading_zeros)                          | `leading_ones`  | :heavy\_check\_mark: | N/A                        |
| [Oblivious Pseudo Random Generation](https://docs.rs/tfhe/latest/tfhe/struct.FheInt.html#method.generate_oblivious_pseudo_random) | `oprf`          | :heavy\_check\_mark: | N/A                        |

{% hint style="info" %}
All operations follow the same syntax as the one described in [here](../../fhe-computation/operations/README.md).
{% endhint %}
