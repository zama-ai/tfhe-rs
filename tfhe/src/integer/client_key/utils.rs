// Tools to compute the inverse Chinese Remainder Theorem
pub(crate) fn extended_euclid(f: i64, g: i64) -> (usize, Vec<i64>, Vec<i64>, Vec<i64>, Vec<i64>) {
    let mut s: Vec<i64> = vec![1, 0];
    let mut t: Vec<i64> = vec![0, 1];
    let mut r: Vec<i64> = vec![f, g];
    let mut q: Vec<i64> = vec![0];
    let mut i = 1;
    while r[i] != 0 {
        q.push(r[i - 1] / r[i]); //q[i]
        r.push(r[i - 1] - q[i] * r[i]); //r[i+1]
        s.push(s[i - 1] - q[i] * s[i]); //s[i+1]
        t.push(t[i - 1] - q[i] * t[i]); //t[i+1]
        i += 1;
    }
    let l: usize = i - 1;
    (l, r, s, t, q)
}

pub(crate) fn i_crt(modulus: &[u64], val: &[u64]) -> u64 {
    let big_mod = modulus.iter().product::<u64>();
    let mut c: Vec<u64> = vec![0; val.len()];
    let mut out: u64 = 0;

    for i in 0..val.len() {
        let tmp_mod = big_mod / modulus[i];
        let (l, _, s, _, _) = extended_euclid(tmp_mod as i64, modulus[i] as i64);
        let sl: u64 = if s[l] < 0 {
            //a is positive
            (s[l] % modulus[i] as i64 + modulus[i] as i64) as u64
        } else {
            s[l] as u64
        };
        c[i] = val[i].wrapping_mul(sl);
        c[i] %= modulus[i];

        out = out.wrapping_add(c[i] * tmp_mod);
    }
    out % big_mod
}
