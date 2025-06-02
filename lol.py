def div(N, D, BITS):
    R = N
    Q = 0
    B = 1 << (BITS - 1)

    for i in reversed(range(BITS)):
        print(f"i: {i}, B = {B}, D * B = {D * B}")
        if R >= D * B:
            print("It fits")
            Q += B
            R -= D * B

        B >>= 1

    return Q, R

def div_tfhe_rs(N, D, BITS):
    R = 0
    Q = 0

    for i in reversed(range(BITS)):
        R <<= 1
        R |= (N >> i) & 1
        if R >= D:
            Q |= 1 << i
            R -= D

    return Q, R

for i in range(256):
    for j in range(1, 256):
        print(f"{i} / {j}")
        Q, R = div_tfhe_rs(i, j, 8)
        assert R == i % j, f"For remainder, expected: {i % j}, got {R}"
        assert Q == i // j, f"For quotient, expected: {i // j}, got {Q}"


print(div_tfhe_rs(234, 0, 8))
print(div(234, 0, 8))

