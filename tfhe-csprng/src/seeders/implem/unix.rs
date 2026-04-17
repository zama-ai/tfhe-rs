use crate::seeders::{Seed, Seeder};

/// A seeder which uses the OS entropy source via the [`getrandom`](https://docs.rs/getrandom)
/// crate.
///
/// On Unix-like systems, this uses `getrandom` or `getentropy` when available, otherwise
/// `/dev/urandom` (after polling `/dev/random` as implemented by `getrandom`).
///
/// On Windows, this uses the system APIs backed by `getrandom` (for example `BCryptGenRandom`).
pub struct UnixSeeder {
    secret: u128,
}

impl UnixSeeder {
    /// Creates a new seeder from a user defined secret.
    ///
    /// Important:
    /// ----------
    ///
    /// This secret is used to ensure the quality of the seed in scenarios where the system random
    /// source may be compromised.
    ///
    /// The attack hypotheses are as follow:
    /// - The kernel random output can be predicted by a process running on the machine by just
    ///   observing various states of the machine
    /// - The attacker cannot read data from the process where `tfhe-csprng` is running
    ///
    /// Using a secret in `tfhe-csprng` allows to generate values that the attacker cannot
    /// predict, making this seeder secure on systems were the kernel random outputs can be
    /// predicted.
    pub fn new(secret: u128) -> UnixSeeder {
        UnixSeeder { secret }
    }
}

impl Seeder for UnixSeeder {
    /// Draws entropy from a system source to seed a CSPRNG.
    ///
    /// It may be blocking at system startup if the kernel entropy pool has not been initialized,
    /// but should not be blocking after.
    ///
    /// # Panics
    /// This may panic if the platform cannot provide entropy through `getrandom`.
    fn seed(&mut self) -> Seed {
        let output = self.secret ^ get_system_entropy();

        Seed(output)
    }

    fn is_available() -> bool {
        cfg!(any(target_family = "unix", target_os = "windows"))
    }
}

fn get_system_entropy() -> u128 {
    let mut buf = [0u8; 16];
    // On Linux this prefers the getrandom syscall when available. On Windows, getrandom uses the
    // appropriate system RNG. See the getrandom crate for per-OS behavior.
    getrandom::getrandom(&mut buf).expect("Failed to read entropy from system");
    // For consistency between big and small endian, Seed exposing accidentally the endianness via
    // the pub u128 field
    u128::from_le_bytes(buf)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::seeders::generic_tests::check_seeder_fixed_sequences_different;

    #[test]
    fn check_bounded_sequence_difference() {
        check_seeder_fixed_sequences_different(UnixSeeder::new);
    }
}
