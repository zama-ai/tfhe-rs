import itertools

def main():
    msg_carry_bits = [1, 2, 3, 4]
    security = list(range(128, 139))
    p_fails = [40, 64, 80, 128]

    for (msg_carry_bit, sec, p_fail) in itertools.product(msg_carry_bits, security, p_fails):
        print(f"PARAM_PKE_MESSAGE_{msg_carry_bit}_CARRY_{msg_carry_bit}_{sec}_{p_fail}")
        print(f"PARAM_FHE_MESSAGE_{msg_carry_bit}_CARRY_{msg_carry_bit}_{sec}_{p_fail}")

    for (msg_carry_bit, sec, p_fail) in itertools.product(msg_carry_bits, security, p_fails):
        print(f"(PARAM_PKE_MESSAGE_{msg_carry_bit}_CARRY_{msg_carry_bit}_{sec}_{p_fail},"
              f"PARAM_FHE_MESSAGE_{msg_carry_bit}_CARRY_{msg_carry_bit}_{sec}_{p_fail},"
              f"PARAM_KEYSWITCH_MESSAGE_{msg_carry_bit}_CARRY_{msg_carry_bit}_{sec}_{p_fail})")

if __name__ == "__main__":
    main()
