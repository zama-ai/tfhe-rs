use crate::{
    fastdiv::Div64,
    prime::{exp_mod64, mul_mod64},
};

pub const fn get_q_s64(p: Div64) -> (u64, u64) {
    let p = p.divisor();
    let mut q = p - 1;
    let mut s = 0;
    while q % 2 == 0 {
        q /= 2;
        s += 1;
    }
    (q, s)
}

pub const fn get_z64(p: Div64) -> Option<u64> {
    let p_val = p.divisor();

    let mut n = 2;
    while n < p_val {
        if exp_mod64(p, n, (p_val - 1) / 2) == p_val - 1 {
            return Some(n);
        }
        n += 1;
    }
    None
}

/// <https://en.wikipedia.org/wiki/Tonelli-Shanks_algorithm#The_algorithm>
pub const fn sqrt_mod_ex64(p: Div64, q: u64, s: u64, z: u64, n: u64) -> Option<u64> {
    let mut m = s;
    let mut c = exp_mod64(p, z, q);
    let mut t = exp_mod64(p, n, q);
    let mut r = exp_mod64(p, n, q.div_ceil(2));

    loop {
        if t == 0 {
            return Some(0);
        }
        if t == 1 {
            return Some(r);
        }

        let mut i = 0;
        let mut t_pow = t;
        while i < m {
            t_pow = mul_mod64(p, t_pow, t_pow);
            i += 1;
            if t_pow == 1 {
                break;
            }
        }
        let i = i;
        if i == m {
            assert!(t_pow == 1);
            return None;
        }

        let b = exp_mod64(p, c, 1 << (m - i - 1));
        m = i;
        c = mul_mod64(p, b, b);
        t = mul_mod64(p, t, c);
        r = mul_mod64(p, r, b);
    }
}

pub const fn find_primitive_root64(p: Div64, degree: u64) -> Option<u64> {
    assert!(degree.is_power_of_two());
    assert!(degree > 1);
    let n = degree.trailing_zeros();

    let p_val = p.divisor();
    let mut root = p_val - 1;
    let (q, s) = get_q_s64(p);
    let z = match get_z64(p) {
        Some(z) => z,
        None => return None,
    };

    let mut i = 0;
    while i < n - 1 {
        root = match sqrt_mod_ex64(p, q, s, z, root) {
            Some(r) => r,
            None => return None,
        };
        i += 1;
    }

    Some(root)
}

/// Returns the n-th root of unity in the solinas prime
///
/// Returns `None` if n == 0 or is greater than 2^32
pub const fn find_root_solinas_64(p: Div64, n: u64) -> Option<u64> {
    if n == 0 || n > (1u64 << 32) {
        return None;
    }

    // 2^32th root of unity
    const OMG_2_32: u64 = 16334397945464290598;

    let pow = (1u64 << 32) / n;

    Some(exp_mod64(p, OMG_2_32, pow))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fastdiv::Div64, prime::largest_prime_in_arithmetic_progression64};

    const fn sqrt_mod64(p: Div64, n: u64) -> Option<u64> {
        if p.divisor() == 2 {
            Some(n)
        } else {
            let z = match get_z64(p) {
                Some(z) => z,
                None => panic!(),
            };
            let (q, s) = get_q_s64(p);
            sqrt_mod_ex64(p, q, s, z, n)
        }
    }

    #[test]
    fn test_sqrt() {
        let p_val = largest_prime_in_arithmetic_progression64(1 << 10, 1, 0, u64::MAX).unwrap();
        let p = Div64::new(p_val);
        let i = sqrt_mod64(p, p_val - 1).unwrap();
        let j = sqrt_mod64(p, i).unwrap();
        assert_eq!(mul_mod64(p, i, i), p_val - 1);
        assert_eq!(mul_mod64(p, j, j), i);
    }

    #[test]
    fn test_primitive_root() {
        let deg = 1 << 10;
        let p_val = largest_prime_in_arithmetic_progression64(deg, 1, 0, u64::MAX).unwrap();
        let p = Div64::new(p_val);
        let root = find_primitive_root64(p, deg).unwrap();
        for i in 1..deg {
            assert_ne!(exp_mod64(p, root, i), 1);
        }
        assert_eq!(exp_mod64(p, root, deg), 1);
    }

    #[test]
    fn test_primitive_root_solinas() {
        let p = Div64::new(super::super::prime64::SOLINAS_PRIME);
        let input_result = [
            (32, 8_u64),
            (64, 2198989700608_u64),
            (128, 14041890976876060974_u64),
            (256, 14430643036723656017_u64),
            (512, 4440654710286119610_u64),
            (1024, 8816101479115663336_u64),
            (2048, 10974926054405199669_u64),
            (4096, 1206500561358145487_u64),
            (8192, 10930245224889659871_u64),
            (16384, 3333600369887534767_u64),
            (32768, 15893793146607301539_u64),
        ];
        for (poly_size, expected_root) in input_result {
            assert_eq!(
                expected_root,
                find_root_solinas_64(p, 2 * poly_size).unwrap()
            );
            assert_eq!(exp_mod64(p, expected_root, 2 * poly_size), 1);
        }
    }
}
