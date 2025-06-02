type T = u8;

fn div(n: u8, d: u8) -> (u8, u8) {
    let mut r = n;
    let mut q = 0;

    let mut b = 1 << (u8::BITS - 1);
    let clz = d.leading_zeros();

    for i in (0..u8::BITS).rev() {
        println!("i: {i}, b: {b}, d* b = {}", d.wrapping_mul(b));

        let (new_remainder, overflowed) = r.overflowing_sub(d.wrapping_mul(b));
        if !overflowed && clz >= i {
            println!("should sub");
            r = new_remainder;
            q += b;
        }
        b >>= 1;
    }

    (q, r)
}

fn div_with_split(n: u8, d: u8) -> (u8, u8) {
    let mut r = n;
    let mut q = 0;

    let mut b = 1 << (u8::BITS - 1);
    let clz = d.leading_zeros();

    for i in (0..u8::BITS).rev() {
        // println!("i: {i}, b: {b}, d* b = {}", d.wrapping_mul(b));

        // We know bits of (d * b) from 0..i are zeros
        // because b is a power of two, so d * b shift bits of d

        let m = d.wrapping_mul(b);

        let high_m = m >> i;
        let high_r = r >> i;
        let low_r = r & ((1 << i) - 1);
        let (new_high_r, overflowed) = high_r.overflowing_sub(high_m);

        if !overflowed && clz >= i {
            // println!("should sub");
            r = (new_high_r << i) | low_r;
            q += b;
        }
        b >>= 1;
    }

    (q, r)
}

// Thi
fn div_with_other_split(n: u8, d: u8) -> (u8, u8) {
    let mut r = n;
    let mut q = 0;

    let mut b = 1 << (u8::BITS - 1);

    for i in (0..u8::BITS).rev() {
        // println!("i: {i}, b: {b}, d* b = {}", d.wrapping_mul(b));

        // We know bits of (d * b) from 0..i are zeros
        // because b is a power of two, so d * b shift bits of d

        let m = d.wrapping_mul(b);

        let high_m = m >> i;
        let high_r = r >> i;
        let low_r = r & ((1 << i) - 1);
        let high_d = if i == 0 { 0 } else { d >> (u8::BITS - i) };
        // println!("{high_d:08b} (d = {d}, s: {})", (u8::BITS - i));

        let (new_high_r, overflowed) = high_r.overflowing_sub(high_m);

        if !overflowed && high_d == 0 {
            // println!("should sub");
            r = (new_high_r << i) | low_r;
            q += b;
        }
        b >>= 1;
    }

    (q, r)
}

fn main() {
    let (i, j) = (1, 1);
    let (q, r) = div_with_other_split(i, j);
    assert_eq!(q, i / j);
    assert_eq!(r, i % j);

    for i in 0..T::MAX {
        for j in 1..T::MAX {
            let (q, r) = div_with_other_split(i, j);
            assert_eq!(q, i / j, "fail for {i} / {j}");
            assert_eq!(r, i % j);
        }
    }

    println!("Ok");
}
