# GPU operations
This document outlines the GPU operations supported in TFHE-rs. 

The GPU backend includes the following operations for both signed and unsigned encrypted integers:

| name                               | symbol                | `Enc`/`Enc`          | `Enc`/ `Int`               |
|------------------------------------|-----------------------|----------------------|----------------------------|
| Neg                                | `-`                   | :heavy\_check\_mark: | N/A                        |
| Add                                | `+`                   | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Sub                                | `-`                   | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Mul                                | `*`                   | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Div                                | `/`                   | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Rem                                | `%`                   | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Not                                | `!`                   | :heavy\_check\_mark: | N/A                        |
| BitAnd                             | `&`                   | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| BitOr                              | `\|`                  | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| BitXor                             | `^`                   | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Shr                                | `>>`                  | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Shl                                | `<<`                  | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Rotate right                       | `rotate_right`        | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Rotate left                        | `rotate_left`         | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Min                                | `min`                 | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Max                                | `max`                 | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Greater than                       | `gt`                  | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Greater or equal than              | `ge`                  | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Lower than                         | `lt`                  | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Lower or equal than                | `le`                  | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Equal                              | `eq`                  | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Not Equal                          | `ne`                  | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Cast (into dest type)              | `cast_into`           | :heavy\_check\_mark: | N/A                        |
| Cast (from src type)               | `cast_from`           | :heavy\_check\_mark: | N/A                        |
| Ternary operator                   | `select`              | :heavy\_check\_mark: | :heavy\_multiplication\_x: |
| Integer logarithm                  | `ilog2`               | :heavy\_check\_mark: | N/A                        |
| Count trailing/leading zeros/ones  | `count_leading_zeros` | :heavy\_check\_mark: | N/A                        |
| Oblivious Pseudo Random Generation | `oprf`                | :heavy\_check\_mark: | N/A                        |

{% hint style="info" %}
All operations follow the same syntax as the one described in [here](../../fhe-computation/operations/README.md).
{% endhint %}
