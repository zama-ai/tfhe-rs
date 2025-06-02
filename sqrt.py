import math

def sqrt(V, BITS):
    R = 0

    B = 1 << BITS - 1
    B_SQUARED = B << BITS - 1

    for _ in range(BITS):
        TMP = 2*B*R + B_SQUARED
        if V >= TMP:
            R |= B
            V -= TMP

        B >>= 1
        B_SQUARED >>= 2

    return R


# Use the fact that V is in [0, 2**BITS[
def sqrt2(V, BITS):
    R = 0

    B = 1 << (BITS // 2) - 1
    B_SQUARED = B << (BITS // 2) - 1

    for _ in range(BITS // 2):
        TMP = 2*B*R + B_SQUARED
        if V >= TMP:
            R |= B
            V -= TMP

        B >>= 1
        B_SQUARED >>= 2

    return R

R = sqrt2(144, 8)
print(R)

for i in range(2**16):
    print(f"{i}")
    R = sqrt(i, 16)
    assert R == int(math.sqrt(i)), f"For sqrt {i}, expected: {int(math.sqrt(i))}, got {R}"


