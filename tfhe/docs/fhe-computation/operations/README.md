# Operations

This document gives a high-level overview of various operations on encrypted integers supported by **TFHE-rs.**

**TFHE-rs** supports various operations on encrypted integers (`Enc`) of any size between 1 and 256 bits. These operations can also work between encrypted integers and clear integers (`Int`).

| name                  | symbol      | `Enc`/`Enc`          | `Enc`/ `Int`               |
| --------------------- | ----------- | -------------------- | -------------------------- |
| Neg                   | `-`         | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Add                   | `+`         | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Sub                   | `-`         | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Mul                   | `*`         | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Div                   | `/`         | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Rem                   | `%`         | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Not                   | `!`         | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| BitAnd                | `&`         | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| BitOr                 | `\|`        | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| BitXor                | `^`         | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Shr                   | `>>`        | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Shl                   | `<<`        | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Min                   | `min`       | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Max                   | `max`       | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Greater than          | `gt`        | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Greater or equal than | `ge`        | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Less than             | `lt`        | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Less or equal than    | `le`        | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Equal                 | `eq`        | :heavy\_check\_mark: | :heavy\_check\_mark:       |
| Cast (into dest type) | `cast_into` | :heavy\_check\_mark: | :heavy\_multiplication\_x: |
| Cast (from src type)  | `cast_from` | :heavy\_check\_mark: | :heavy\_multiplication\_x: |
| Ternary operator      | `select`    | :heavy\_check\_mark: | :heavy\_multiplication\_x: |
