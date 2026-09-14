use crate::fastdiv::{Div32, Div64};

pub(crate) struct BarrettInit {
    pub(crate) big_q: u32,
    pub(crate) p_barrett: u128,
    pub(crate) requires_single_barrett_reduction_step: bool,
}

impl BarrettInit {
    /// Applies the criterion that can be found in
    /// implementation_notes/tfhe-ntt/gh_issue_2037_barrett_range.md to decide whether a prime is a
    /// "fast" prime for Barrett
    ///
    /// # Panics
    ///
    /// Panics if $p < 2$, if `register_width` is $< 2$ or $> 64$ and if
    /// $p >= 2^(register_width - 1)$
    pub(crate) fn new(p: u64, register_width: u32) -> BarrettInit {
        let w = register_width;
        assert!(p >= 2);
        assert!((2..=64).contains(&w));

        // k == Q - 1
        // where 2^k       <= p <= 2^(k + 1)
        // or    2^(Q - 1) <= p <= 2^Q
        let k = p.ilog2();
        let big_q = k + 1;
        let p = u128::from(p);

        assert!(
            p < (1u128 << register_width),
            "Got prime larger than register"
        );

        // p larger than half the register, no way to have a single reduction without overflow
        if p >= 1u128 << (w - 1) {
            // Fine to return big_q and p_barrett set at 0 since we cannot fulfill the single
            // reduction criterion, their values go unused in the ntt code
            return BarrettInit {
                big_q: 0,
                p_barrett: 0,
                requires_single_barrett_reduction_step: false,
            };
        }

        // L = Q - 1 + w == k + w
        // w <= 64 and k + 1 <= w - 1 <= 63 => k <= 62
        let big_l = k + w;
        let two_to_the_l = 1u128.checked_shl(big_l).expect("Should not fail");
        // floor(2^L / p), 2^L mod p
        let (p_barrett, beta) = (two_to_the_l / p, two_to_the_l % p);
        // c1_max = floor(d_max / 2^k) where d_max product of two values mod p so d_max = (p - 1)^2
        let c1_max = ((p - 1) * (p - 1)) >> k;

        // 2^k
        let two_pow_k = 1u128 << k;
        // c1_max * beta < (p - 2^k + 1) * 2^w
        let requires_single_barrett_reduction_step = c1_max * beta < (p - two_pow_k + 1) << w;

        BarrettInit {
            big_q,
            p_barrett,
            requires_single_barrett_reduction_step,
        }
    }
}

#[inline(always)]
pub const fn mul_mod32(n: Div32, x: u32, y: u32) -> u32 {
    Div32::rem_u64(x as u64 * y as u64, n)
}
#[inline(always)]
pub const fn mul_mod64(n: Div64, x: u64, y: u64) -> u64 {
    Div64::rem_u128(x as u128 * y as u128, n)
}

pub const fn exp_mod32(n: Div32, base: u32, pow: u32) -> u32 {
    if pow == 0 {
        1
    } else {
        let mut pow = pow;
        let mut y = 1;
        let mut x = base;

        while pow > 1 {
            if pow % 2 == 1 {
                y = mul_mod32(n, x, y);
            }
            x = mul_mod32(n, x, x);
            pow /= 2;
        }
        mul_mod32(n, x, y)
    }
}

pub const fn exp_mod64(n: Div64, base: u64, pow: u64) -> u64 {
    if pow == 0 {
        1
    } else {
        let mut pow = pow;
        let mut y = 1;
        let mut x = base;

        while pow > 1 {
            if pow % 2 == 1 {
                y = mul_mod64(n, x, y);
            }
            x = mul_mod64(n, x, x);
            pow /= 2;
        }
        mul_mod64(n, x, y)
    }
}

const fn is_prime_miller_rabin_iter(n: Div64, s: u64, d: u64, a: u64) -> bool {
    let mut x = exp_mod64(n, a, d);
    let n_minus_1 = n.divisor() - 1;
    if x == 1 || x == n_minus_1 {
        true
    } else {
        let mut count = 0;
        while count < s - 1 {
            x = mul_mod64(n, x, x);
            if x == n_minus_1 {
                return true;
            }
            count += 1;
        }
        false
    }
}

const fn max64(a: u64, b: u64) -> u64 {
    if a > b {
        a
    } else {
        b
    }
}

pub const fn is_prime64(n: u64) -> bool {
    // 0 and 1 are not prime
    if n < 2 {
        return false;
    }

    // test divisibility by small primes
    // hand-unrolled for the compiler to optimize divisions
    #[rustfmt::skip]
    {
        if n.is_multiple_of(2) { return n ==  2; }
        if n.is_multiple_of(3) { return n ==  3; }
        if n.is_multiple_of(5) { return n ==  5; }
        if n.is_multiple_of(7) { return n ==  7; }
        if n.is_multiple_of(11) { return n == 11; }
        if n.is_multiple_of(13) { return n == 13; }
        if n.is_multiple_of(17) { return n == 17; }
        if n.is_multiple_of(19) { return n == 19; }
        if n.is_multiple_of(23) { return n == 23; }
        if n.is_multiple_of(29) { return n == 29; }
        if n.is_multiple_of(31) { return n == 31; }
        if n.is_multiple_of(37) { return n == 37; }
    };

    // deterministic miller rabin test, works for any n < 2^64
    // aside from the primes tested just before

    // https://en.wikipedia.org/wiki/Miller-Rabin_primality_test#Testing_against_small_sets_of_bases
    let mut s = 0;
    let mut d = n - 1;

    while d.is_multiple_of(2) {
        s += 1;
        d /= 2;
    }

    let (s, d) = (s, d);
    let n = Div64::new(n);
    is_prime_miller_rabin_iter(n, s, d, 2)
        && is_prime_miller_rabin_iter(n, s, d, 3)
        && is_prime_miller_rabin_iter(n, s, d, 5)
        && is_prime_miller_rabin_iter(n, s, d, 7)
        && is_prime_miller_rabin_iter(n, s, d, 11)
        && is_prime_miller_rabin_iter(n, s, d, 13)
        && is_prime_miller_rabin_iter(n, s, d, 17)
        && is_prime_miller_rabin_iter(n, s, d, 19)
        && is_prime_miller_rabin_iter(n, s, d, 23)
        && is_prime_miller_rabin_iter(n, s, d, 29)
        && is_prime_miller_rabin_iter(n, s, d, 31)
        && is_prime_miller_rabin_iter(n, s, d, 37)
}

/// Largest prime of the form `factor * x + offset` in the range
/// `[lo, hi]`.
pub const fn largest_prime_in_arithmetic_progression64(
    factor: u64,
    offset: u64,
    lo: u64,
    hi: u64,
) -> Option<u64> {
    if lo > hi {
        return None;
    }

    let a = factor;
    let b = offset;
    // lo <= ax + b <= hi
    // (lo - b)/a <= x <= (hi - b)/a

    if b > hi {
        return None;
    }

    if a == 0 {
        if lo <= b && b <= hi && is_prime64(b) {
            return Some(b);
        } else {
            return None;
        }
    }

    let mut x_lo = (max64(lo, b) - b) / a;
    let rem = (max64(lo, b) - b) % a;
    if rem != 0 {
        x_lo += 1;
    }

    let x_hi = (hi - b) / a;

    // No element of the progression falls in [lo, hi].
    if x_hi < x_lo {
        return None;
    }

    let mut x = x_hi;
    let mut in_range = true;
    while in_range {
        let val = a * x + b;
        if is_prime64(val) {
            return Some(val);
        }

        if x == x_lo {
            in_range = false;
        } else {
            x -= 1;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prime64::Solinas;

    #[test]
    fn test_is_prime() {
        let primes_under_1000 = [
            2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83,
            89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
            181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271,
            277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379,
            383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479,
            487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599,
            601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
            709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823,
            827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
            947, 953, 967, 971, 977, 983, 991, 997,
        ];

        for n in 0..1000 {
            assert_eq!(primes_under_1000.contains(&n), is_prime64(n));
        }
        assert!(is_prime64(Solinas::P));
    }

    #[test]
    #[rustfmt::skip]
    fn test_prime_search() {
        assert_eq!(largest_prime_in_arithmetic_progression64(0, 2, 1, 4), Some(2));
        assert_eq!(largest_prime_in_arithmetic_progression64(0, 2, 2, 2), Some(2));
        assert_eq!(largest_prime_in_arithmetic_progression64(0, 2, 2, 1), None);
        assert_eq!(largest_prime_in_arithmetic_progression64(1, 0, 14, 16), None);
        assert_eq!(largest_prime_in_arithmetic_progression64(1, 0, 14, 17), Some(17));
        assert_eq!(largest_prime_in_arithmetic_progression64(1, 0, 17, 18), Some(17));
        assert_eq!(largest_prime_in_arithmetic_progression64(2, 1, 14, 16), None);
        assert_eq!(largest_prime_in_arithmetic_progression64(2, 1, 14, 17), Some(17));
        assert_eq!(largest_prime_in_arithmetic_progression64(2, 1, 17, 18), Some(17));
        assert_eq!(largest_prime_in_arithmetic_progression64(6, 5, 0, u64::MAX) , Some(18446744073709551557));
        assert_eq!(largest_prime_in_arithmetic_progression64(6, 1, 0, u64::MAX) , Some(18446744073709551427));
    }
}
