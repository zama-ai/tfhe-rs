pub mod ciphertext;
pub mod client_key;
pub mod server_key;

mod char_iter;
#[cfg(test)]
mod test_functions;

// Used as the const argument for StaticUnsignedBigInt, specifying the max chars length of a
// ClearString
const N: usize = 32;

#[cfg(test)]
pub(crate) use test::TestKeys;

#[cfg(test)]
mod test {
    use crate::integer::keycache::KEY_CACHE;
    use crate::integer::{ClientKey, ServerKey};
    use crate::shortint::parameters::{
        PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64, PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
        PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    };
    use crate::shortint::ClassicPBSParameters;

    use super::ciphertext::FheString;
    use super::client_key::EncU16;

    #[test]
    fn test_all() {
        for param in [
            PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
            PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64,
            PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
        ] {
            test_all_impl(
                param,
                "a",
                Some(1),
                "a",
                Some(1),
                "a",
                Some(1),
                "a",
                Some(1),
                0,
                0,
                TestKind::Trivial,
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn test_all_impl(
        params: ClassicPBSParameters,
        str: &str,
        str_pad: Option<u32>,
        pat: &str,
        pat_pad: Option<u32>,
        to: &str,
        to_pad: Option<u32>,
        rhs: &str,
        rhs_pad: Option<u32>,
        n: u16,
        max: u16,
        test_kind: TestKind,
    ) {
        let keys = TestKeys::new(params, test_kind);

        keys.check_len_fhe_string_vs_rust_str(str, str_pad);
        keys.check_is_empty_fhe_string_vs_rust_str(str, str_pad);

        keys.check_encrypt_decrypt_fhe_string_vs_rust_str(str, str_pad);

        keys.check_contains_fhe_string_vs_rust_str(str, str_pad, pat, pat_pad);
        keys.check_ends_with_fhe_string_vs_rust_str(str, str_pad, pat, pat_pad);
        keys.check_starts_with_fhe_string_vs_rust_str(str, str_pad, pat, pat_pad);

        keys.check_find_fhe_string_vs_rust_str(str, str_pad, pat, pat_pad);
        keys.check_rfind_fhe_string_vs_rust_str(str, str_pad, pat, pat_pad);

        keys.check_strip_prefix_fhe_string_vs_rust_str(str, str_pad, pat, pat_pad);
        keys.check_strip_suffix_fhe_string_vs_rust_str(str, str_pad, pat, pat_pad);

        keys.check_eq_ignore_case_fhe_string_vs_rust_str(str, str_pad, rhs, rhs_pad);
        keys.check_comp_fhe_string_vs_rust_str(str, str_pad, rhs, rhs_pad);

        keys.check_to_lowercase_fhe_string_vs_rust_str(str, str_pad);
        keys.check_to_uppercase_fhe_string_vs_rust_str(str, str_pad);

        keys.check_concat_fhe_string_vs_rust_str(str, str_pad, rhs, rhs_pad);
        keys.check_repeat_fhe_string_vs_rust_str(str, str_pad, n, max);

        keys.check_trim_end_fhe_string_vs_rust_str(str, str_pad);
        keys.check_trim_start_fhe_string_vs_rust_str(str, str_pad);
        keys.check_trim_fhe_string_vs_rust_str(str, str_pad);
        keys.check_split_ascii_whitespace_fhe_string_vs_rust_str(str, str_pad);

        keys.check_split_once_fhe_string_vs_rust_str(str, str_pad, pat, pat_pad);
        keys.check_rsplit_once_fhe_string_vs_rust_str(str, str_pad, pat, pat_pad);

        keys.check_split_fhe_string_vs_rust_str(str, str_pad, pat, pat_pad);
        keys.check_rsplit_fhe_string_vs_rust_str(str, str_pad, pat, pat_pad);

        keys.check_split_terminator_fhe_string_vs_rust_str(str, str_pad, pat, pat_pad);
        keys.check_rsplit_terminator_fhe_string_vs_rust_str(str, str_pad, pat, pat_pad);
        keys.check_split_inclusive_fhe_string_vs_rust_str(str, str_pad, pat, pat_pad);

        keys.check_splitn_fhe_string_vs_rust_str(str, str_pad, pat, pat_pad, n, max);
        keys.check_rsplitn_fhe_string_vs_rust_str(str, str_pad, pat, pat_pad, n, max);

        keys.check_replace_fhe_string_vs_rust_str(str, str_pad, pat, pat_pad, to, to_pad);
        keys.check_replacen_fhe_string_vs_rust_str(
            (str, str_pad),
            (pat, pat_pad),
            (to, to_pad),
            n,
            max,
        );
    }

    pub(crate) struct TestKeys {
        pub ck: ClientKey,
        pub sk: ServerKey,
        pub test_kind: TestKind,
    }

    pub enum TestKind {
        Trivial,
        Encrypted,
    }

    impl TestKeys {
        pub fn new(params: ClassicPBSParameters, test_kind: TestKind) -> Self {
            let (ck, sk) = KEY_CACHE.get_from_params(params, crate::integer::IntegerKeyKind::Radix);

            Self { ck, sk, test_kind }
        }

        pub fn encrypt_string(&self, str: &str, padding: Option<u32>) -> FheString {
            match self.test_kind {
                TestKind::Trivial => FheString::new_trivial(&self.ck, str, padding),
                TestKind::Encrypted => FheString::new(&self.ck, str, padding),
            }
        }

        pub fn encrypt_u16(&self, val: u16, max: Option<u16>) -> EncU16 {
            match self.test_kind {
                TestKind::Trivial => self.ck.trivial_encrypt_u16(val, max),
                TestKind::Encrypted => self.ck.encrypt_u16(val, max),
            }
        }
    }
}
