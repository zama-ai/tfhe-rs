use crate::seeders::{Seed, Seeder};
use libc;
use std::cmp::Ordering;

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
        // 16 bytes == 128 bits
        let mut bytes = [0u8; 16];
        secure_enclave::generate_random_bytes(&mut bytes)
            .expect("Failure while using Apple secure enclave: {err:?}");

        Seed(u128::from_le_bytes(bytes))
    }

    fn is_available() -> bool {
        let os_version_sysctl_name = match std::ffi::CString::new("kern.osproductversion") {
            Ok(c_str) => c_str,
            _ => return false,
        };

        // Big enough buffer to get a version output as an ASCII string
        const OUTPUT_BUFFER_SIZE: usize = 64;
        let mut output_buffer_size = OUTPUT_BUFFER_SIZE;
        let mut output_buffer = [0u8; OUTPUT_BUFFER_SIZE];
        let res = unsafe {
            libc::sysctlbyname(
                os_version_sysctl_name.as_ptr() as *const _ as *const _,
                &mut output_buffer as *mut _ as *mut _,
                &mut output_buffer_size as *mut _ as *mut _,
                std::ptr::null_mut(),
                0,
            )
        };

        if res != 0 {
            return false;
        }

        let result_c_str =
            match std::ffi::CStr::from_bytes_with_nul(&output_buffer[..output_buffer_size]) {
                Ok(c_str) => c_str,
                _ => return false,
            };

        let result_string = match result_c_str.to_str() {
            Ok(str) => str,
            _ => return false,
        };

        // Normally we get a major version and minor version
        let split_string: Vec<&str> = result_string.split('.').collect();

        let mut major = -1;
        let mut minor = -1;

        // Major part of the version string
        if !split_string.is_empty() {
            major = match split_string[0].parse() {
                Ok(major_from_str) => major_from_str,
                _ => return false,
            };
        }

        // SecRandomCopyBytes is available starting with mac OS 10.7
        // https://developer.apple.com/documentation/security/1399291-secrandomcopybytes?language=objc
        // This match pattern is recommended by clippy, so we oblige here
        match major.cmp(&10) {
            Ordering::Greater => true,
            Ordering::Equal => {
                // Minor part of the version string
                if split_string.len() >= 2 {
                    minor = match split_string[1].parse() {
                        Ok(minor_from_str) => minor_from_str,
                        _ => return false,
                    };
                }
                minor >= 7
            }
            Ordering::Less => false,
        }
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
