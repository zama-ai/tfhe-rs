use crate::seeders::{Seed, Seeder};

/// A seeder which uses the system entropy source on unix-like systems.
///
/// If available, this will use `getrandom` or `getentropy` system call. Otherwise it will draw from
/// `/dev/urandom` after successfully polling `/dev/random`.
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
    /// This may panic if the `getrandom` system call is not available and no file descriptor is
    /// available on the system.
    fn seed(&mut self) -> Seed {
        let output = self.secret ^ get_system_entropy();

        Seed(output)
    }

    fn is_available() -> bool {
        cfg!(target_family = "unix")
    }
}

fn get_system_entropy() -> u128 {
    let mut buf = [0u8; 16];
    // This will use the getrandom syscall if possible (from linux 3.17). This syscall is not
    // vulnerable to fd exhaustion since it directly pulls from kernel entropy sources.
    //
    // This syscall will use the urandom entropy source but block at startup until it is correctly
    // seeded. See <https://www.2uo.de/myths-about-urandom/> for a rational around random/urandom.
    getrandom::fill(&mut buf).expect("Failed to read entropy from system");
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
