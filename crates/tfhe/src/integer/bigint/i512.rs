pub type I512 = super::static_signed::StaticSignedBigInt<8>;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_const() {
        assert_eq!(I512::BITS, 512);
        assert_eq!(I512::ZERO, I512::from([0, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(I512::ONE, I512::from([1, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(I512::TWO, I512::from([2, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(
            I512::MAX,
            I512::from([
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX >> 1
            ])
        );
        assert_eq!(I512::MIN, I512::from([0, 0, 0, 0, 0, 0, 0, 1u64 << 63]));
    }
}
