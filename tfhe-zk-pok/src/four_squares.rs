use ark_ff::biginteger::arithmetic::widening_mul;
use rand::prelude::*;

/// Avoid overflows for squares of u64
pub fn sqr(x: u64) -> u128 {
    let x = x as u128;
    x * x
}

pub fn checked_sqr(x: u128) -> Option<u128> {
    x.checked_mul(x)
}

fn half_gcd(p: u128, s: u128) -> u128 {
    let sq_p = p.isqrt();
    let mut a = p;
    let mut b = s;
    while b > sq_p {
        let r = a % b;
        a = b;
        b = r;
    }
    b
}

fn modular_inv_2_64(p: u64) -> u64 {
    assert_eq!(p % 2, 1);

    let mut old_r = p as u128;
    let mut r = 1u128 << 64;

    let mut old_s = 1u64;
    let mut s = 0u64;

    while r != 0 {
        let q = old_r / r;
        (old_r, r) = (r, old_r - q * r);

        let q = q as u64;
        (old_s, s) = (s, old_s.wrapping_sub(q.wrapping_mul(s)));
    }

    assert_eq!(u64::wrapping_mul(old_s, p), 1);
    old_s
}

#[derive(Copy, Clone, Debug)]
struct Montgomery {
    p: u128,
    r2: u128,
    p_prime: u64,
}

impl Montgomery {
    fn new(p: u128) -> Self {
        assert_ne!(p, 0);
        assert_eq!(p % 2, 1);

        // r = 2^128
        // we want to compute r^2 mod p
        let r = p.wrapping_neg() % p;

        let r = num_bigint::BigUint::from(r);
        let r2 = &r * &r;
        let r2 = r2 % p;
        let r2_digits = &*r2.to_u64_digits();

        let r2 = match *r2_digits {
            [] => 0u128,
            [a] => a as u128,
            [a, b] => a as u128 | ((b as u128) << 64),
            _ => unreachable!("value modulo 128 bit integer should have at most two u64 digits"),
        };

        let p_prime = modular_inv_2_64(p as u64).wrapping_neg();

        Self { p, r2, p_prime }
    }

    fn redc(self, lo: u128, hi: u128) -> u128 {
        let p0 = self.p as u64;
        let p1 = (self.p >> 64) as u64;

        let t0 = lo as u64;
        let mut t1 = (lo >> 64) as u64;
        let mut t2 = hi as u64;
        let mut t3 = (hi >> 64) as u64;
        let mut t4 = 0u64;

        {
            let m = u64::wrapping_mul(t0, self.p_prime);
            let mut c = 0u64;

            let x = c as u128 + t0 as u128 + widening_mul(m, p0);
            // t0 = x as u64;
            c = (x >> 64) as u64;

            let x = c as u128 + t1 as u128 + widening_mul(m, p1);
            t1 = x as u64;
            c = (x >> 64) as u64;

            let x = c as u128 + t2 as u128;
            t2 = x as u64;
            c = (x >> 64) as u64;

            let x = c as u128 + t3 as u128;
            t3 = x as u64;
            c = (x >> 64) as u64;

            t4 += c;
        }

        {
            let m = u64::wrapping_mul(t1, self.p_prime);
            let mut c = 0u64;

            let x = c as u128 + t1 as u128 + widening_mul(m, p0);
            // t1 = x as u64;
            c = (x >> 64) as u64;

            let x = c as u128 + t2 as u128 + widening_mul(m, p1);
            t2 = x as u64;
            c = (x >> 64) as u64;

            let x = c as u128 + t3 as u128;
            t3 = x as u64;
            c = (x >> 64) as u64;

            t4 += c;
        }

        let mut s0 = t2;
        let mut s1 = t3;
        let s2 = t4;

        if !(s2 == 0 && (s1, s0) < (p1, p0)) {
            let borrow;
            (s0, borrow) = u64::overflowing_sub(s0, p0);
            s1 = s1.wrapping_sub(p1).wrapping_sub(borrow as u64);
        }

        s0 as u128 | ((s1 as u128) << 64)
    }

    fn mont_from_natural(self, x: u128) -> u128 {
        self.mul(x, self.r2)
    }

    fn natural_from_mont(self, x: u128) -> u128 {
        self.redc(x, 0)
    }

    fn mul(self, x: u128, y: u128) -> u128 {
        let x0 = x as u64;
        let x1 = (x >> 64) as u64;
        let y0 = y as u64;
        let y1 = (y >> 64) as u64;

        let lolo = widening_mul(x0, y0);
        let lohi = widening_mul(x0, y1);
        let hilo = widening_mul(x1, y0);
        let hihi = widening_mul(x1, y1);

        let lo = lolo;
        let (lo, o0) = u128::overflowing_add(lo, lohi << 64);
        let (lo, o1) = u128::overflowing_add(lo, hilo << 64);

        let hi = hihi + (lohi >> 64) + (hilo >> 64) + (o0 as u128 + o1 as u128);

        self.redc(lo, hi)
    }

    fn exp(self, x: u128, n: u128) -> u128 {
        if n == 0 {
            return 1;
        }
        let mut y = self.mont_from_natural(1);
        let mut x = x;
        let mut n = n;
        while n > 1 {
            if n % 2 == 1 {
                y = self.mul(x, y);
            }
            x = self.mul(x, x);
            n /= 2;
        }
        self.mul(x, y)
    }
}

pub fn four_squares(v: u128) -> [u64; 4] {
    let rng = &mut StdRng::seed_from_u64(0);

    // In the extreme case where the noise is exactly at the bound, v is 0
    if v == 0 {
        return [0; 4];
    }

    let f = v % 4;
    if f == 2 {
        let b = v.isqrt() as u64;

        'main_loop: loop {
            let x = 2 + rng.gen::<u64>() % (b - 2);
            let y = 2 + rng.gen::<u64>() % (b - 2);

            let (sum, o) = u128::overflowing_add(sqr(x), sqr(y));
            if o || sum > v {
                continue 'main_loop;
            }

            let p = v - sum;

            if p == 0 || p == 1 {
                return [0, p as u64, x, y];
            }

            if p % 4 != 1 {
                continue 'main_loop;
            }

            let mut d = p - 1;
            let mut s = 0u32;
            while d % 2 == 0 {
                d /= 2;
                s += 1;
            }
            let d = d;
            let s = s;

            let mont = Montgomery::new(p);
            let a = 2 + (rng.gen::<u128>() % (p - 3));

            let mut sqrt = 0;
            {
                let a = mont.mont_from_natural(a);
                let one = mont.mont_from_natural(1);
                let neg_one = p - one;

                let mut x = mont.exp(a, d);
                let mut y = 0;

                for _ in 0..s {
                    y = mont.mul(x, x);
                    if y == one && x != one && x != neg_one {
                        continue 'main_loop;
                    }
                    if y == neg_one {
                        sqrt = x;
                    }
                    x = y;
                }
                if y != one {
                    continue 'main_loop;
                }
            }
            if sqrt == 0 {
                continue 'main_loop;
            }

            let i = mont.natural_from_mont(sqrt);
            let i = if i <= p / 2 { p - i } else { i };
            let z = half_gcd(p, i) as u64;
            let w = (p - sqr(z)).isqrt() as u64;

            if p != sqr(z) + sqr(w) {
                continue 'main_loop;
            }

            return [x, y, z, w];
        }
    } else if f == 0 {
        four_squares(v / 4).map(|x| x + x)
    } else {
        let mut r = four_squares(2 * v);
        r.sort_by_key(|&x| {
            if x % 2 == 0 {
                -1 - ((x / 2) as i64)
            } else {
                (x / 2) as i64
            }
        });
        [
            (r[0] + r[1]) / 2,
            (r[0] - r[1]) / 2,
            (r[3] + r[2]) / 2,
            (r[3] - r[2]) / 2,
        ]
    }
}
