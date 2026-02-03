use crate::shortint::server_key::expanded::ShortintExpandedBootstrappingKey;

pub enum ExpandedAtomicPatternNoiseSquashingKey {
    Standard(ShortintExpandedBootstrappingKey<u128, u64>),
    KeySwitch32(ShortintExpandedBootstrappingKey<u128, u32>),
}
