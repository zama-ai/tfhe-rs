use crate::seeders::{Seed, Seeder};

/// There is no `rseed` equivalent in the ARM specification until `ARMv8.5-A`.
/// However it seems that these instructions are not exposed in `core::arch::aarch64`.
///
/// Our primary interest for supporting aarch64 targets is AppleSilicon support
/// which for the M1 macs available, they are based on the `ARMv8.4-A` set.
///
/// So we fall back to using a function from Apple's API which
/// uses the [Secure Enclave] to generate cryptographically secure random bytes.
///
/// [Secure Enclave]: https://support.apple.com/fr-fr/guide/security/sec59b0b31ff/web
mod secure_enclave {
    pub enum __SecRandom {}
    pub type SecRandomRef = *const __SecRandom;
    use libc::{c_int, c_void};

    #[link(name = "Security", kind = "framework")]
    extern "C" {
        pub static kSecRandomDefault: SecRandomRef;

        pub fn SecRandomCopyBytes(rnd: SecRandomRef, count: usize, bytes: *mut c_void) -> c_int;
    }

    pub fn generate_random_bytes(bytes: &mut [u8]) -> std::io::Result<()> {
        // As per Apple's documentation:
        // - https://developer.apple.com/documentation/security/randomization_services?language=objc
        // - https://developer.apple.com/documentation/security/1399291-secrandomcopybytes?language=objc
        //
        // The `SecRandomCopyBytes` "Generate cryptographically secure random numbers"
        unsafe {
            let res = SecRandomCopyBytes(
                kSecRandomDefault,
                bytes.len(),
                bytes.as_mut_ptr() as *mut c_void,
            );
            if res != 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }
}

/// A seeder which uses the `SecRandomCopyBytes` function from Apple's `Security` framework.
///
/// <https://developer.apple.com/documentation/security/1399291-secrandomcopybytes?language=objc>
pub struct AppleSecureEnclaveSeeder;

impl Seeder for AppleSecureEnclaveSeeder {
    fn seed(&mut self) -> Seed {
        let mut bytes = [0u8; std::mem::size_of::<u128>() / std::mem::size_of::<u8>()];
        secure_enclave::generate_random_bytes(&mut bytes)
            .expect("Failure while using Apple secure enclave: {err:?}");

        Seed(u128::from_le_bytes(bytes))
    }

    fn is_available() -> bool {
        // SecRandomCopyBytes is available starting with macOS 10.7
        // https://developer.apple.com/documentation/security/1399291-secrandomcopybytes?language=objc
        //
        // Since Rust 1.74, rust supports macOS >= 10.12
        // https://blog.rust-lang.org/2023/09/25/Increasing-Apple-Version-Requirements.html
        // Thus SecRandomCopyBytes is always expected to be available
        true
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::seeders::generic_tests::check_seeder_fixed_sequences_different;

    #[test]
    fn check_bounded_sequence_difference() {
        check_seeder_fixed_sequences_different(|_| AppleSecureEnclaveSeeder);
    }
}
