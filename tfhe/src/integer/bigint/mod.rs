mod algorithms;
pub mod u256;
pub mod u512;

#[cfg(test)]
fn u64_with_odd_bits_set() -> u64 {
    let mut v = 0u64;

    for i in (1..=63).step_by(2) {
        v |= 1u64 << i;
    }

    v
}
#[cfg(test)]
fn u64_with_even_bits_set() -> u64 {
    let mut v = 0u64;

    // bit index are from 0 to 63
    for i in (0..=62).step_by(2) {
        v |= 1u64 << i;
    }

    v
}
