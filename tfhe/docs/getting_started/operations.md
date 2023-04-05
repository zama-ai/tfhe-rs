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

A walk-through using homomorphic Booleans can be found [here](../Boolean/tutorial.md).

## Shortint

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
The division operation implements a subtlety: since data is encrypted, it might be possible to compute a division by 0. The division is tweaked so that dividing by 0 returns 0.
{% endhint %}

A walk-through example can be found [here](../shortint/tutorial.md), and more examples and explanations can be found [here](../shortint/operations.md).

## Integer

In TFHE-rs, integers represent unsigned integers up to 256 bits. They are encoded using Radix representations by default (more details [here](../integer/operations.md)).

The list of supported operations is:

| Operation name                  | Type   |
| ------------------------------  | ------ |
| Negation                        | Unary  |
| Addition                        | Binary |
| Subtraction                     | Binary |
| Multiplication                  | Binary |
| Bitwise OR, AND, XOR            | Binary |
| Equality                        | Binary |
| Left/Right Shift                | Binary |
| Comparisons `<`,`<=`,`>`, `>=`  | Binary |
| Min, Max                        | Binary |

A walk-through example can be found [here](../integer/tutorial.md).
