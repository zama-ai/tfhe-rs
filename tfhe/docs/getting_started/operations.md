# Supported Operations

## Boolean

The list of supported operations by the homomorphic Booleans is:

| Operation Name | type    |
| -------------- | ------- |
| `not`          | Unary   |
| `and`          | Binary  |
| `or`           | Binary  |
| `xor`          | Binary  |
| `nor`          | Binary  |
| `xnor`         | Binary  |
| `cmux`         | Ternary |

A walk-through using homomorphic Booleans can be found [here](../Booleans/tutorial.md).

## ShortInt

In TFHE-rs, shortint represents short unsigned integers encoded over a maximum of 8 bits. A complete homomorphic arithmetic is provided, along with the possibility to compute univariate and bi-variate functions. Some operations are only available for integers up to 4 bits. More technical details can be found [here](../shortint/operations.md).

The list of supported operations is:

| Operation name            | Type         |
| ------------------------- | ------------ |
| Negation                  | Unary        |
| Addition                  | Binary       |
| Subtraction               | Binary       |
| Multiplication            | Binary       |
| Division\*                | Binary       |
| Modular reduction         | Binary       |
| Comparisons               | Binary       |
| Left/Right Shift          | Binary       |
| And                       | Binary       |
| Or                        | Binary       |
| Xor                       | Binary       |
| Exact Function Evaluation | Unary/Binary |

{% hint style="info" %}
\* The division operation implements a subtlety: since data is encrypted, it might be possible to compute a division by 0. In this case, the division is tweaked so that dividing by 0 returns 0.
{% endhint %}

A walk-through example can be found [here](../shortint/tutorial.md), and more examples and explanations can be found [here](../shortint/operations.md).[ ](../shortint/operations.md)
