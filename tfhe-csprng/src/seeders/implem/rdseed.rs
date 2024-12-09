use crate::seeders::{Seed, Seeder};

/// A seeder which uses the `rdseed` x86_64 instruction.
///
/// The `rdseed` instruction allows to deliver seeds from a hardware source of entropy see
/// <https://www.felixcloutier.com/x86/rdseed> .
pub struct RdseedSeeder(());

impl RdseedSeeder {
    pub fn new() -> Self {
        if Self::is_available() {
            Self(())
        } else {
            panic!("Tried to use RdSeedSeeder but rdseed instruction is not enabled on the current machine");
        }
    }
}

impl Default for RdseedSeeder {
    fn default() -> Self {
        Self::new()
    }
}

impl Seeder for RdseedSeeder {
    fn seed(&mut self) -> Seed {
        Seed(unsafe { rdseed_random_m128() })
    }

    fn is_available() -> bool {
        is_x86_feature_detected!("rdseed")
    }
}

// Generates a random 128 bits value from rdseed
#[target_feature(enable = "rdseed")]
unsafe fn rdseed_random_m128() -> u128 {
    let mut rand1: u64 = 0;
    let mut rand2: u64 = 0;
    let mut output_bytes = [0u8; 16];
    unsafe {
        loop {
            if core::arch::x86_64::_rdseed64_step(&mut rand1) == 1 {
                break;
            }
        }
        loop {
            if core::arch::x86_64::_rdseed64_step(&mut rand2) == 1 {
                break;
            }
        }
    }
    output_bytes[0..8].copy_from_slice(&rand1.to_ne_bytes());
    output_bytes[8..16].copy_from_slice(&rand2.to_ne_bytes());
    u128::from_ne_bytes(output_bytes)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::seeders::generic_tests::check_seeder_fixed_sequences_different;

    #[test]
    fn check_bounded_sequence_difference() {
        check_seeder_fixed_sequences_different(|_| RdseedSeeder::new());
    }
}
