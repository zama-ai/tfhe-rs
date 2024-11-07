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
pub(crate) use test::Keys;

#[cfg(test)]
mod test {
    use crate::integer::keycache::KEY_CACHE;
    use crate::integer::{ClientKey, ServerKey};
    use crate::shortint::parameters::{
        PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64, PARAM_MESSAGE_4_CARRY_4_KS_PBS_GAUSSIAN_2M64,
    };
    use crate::shortint::prelude::PARAM_MESSAGE_2_CARRY_2;
    use crate::shortint::ClassicPBSParameters;

    #[test]
    fn test_all() {
        for param in [
            PARAM_MESSAGE_1_CARRY_1_KS_PBS_GAUSSIAN_2M64,
            PARAM_MESSAGE_2_CARRY_2,
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
    ) {
        let keys = Keys::new(params);

        keys.assert_len(str, str_pad);
        keys.assert_is_empty(str, str_pad);

        keys.assert_encrypt_decrypt(str, str_pad);

        keys.assert_contains(str, str_pad, pat, pat_pad);
        keys.assert_ends_with(str, str_pad, pat, pat_pad);
        keys.assert_starts_with(str, str_pad, pat, pat_pad);

        keys.assert_find(str, str_pad, pat, pat_pad);
        keys.assert_rfind(str, str_pad, pat, pat_pad);

        keys.assert_strip_prefix(str, str_pad, pat, pat_pad);
        keys.assert_strip_suffix(str, str_pad, pat, pat_pad);

        keys.assert_eq_ignore_case(str, str_pad, rhs, rhs_pad);
        keys.assert_comp(str, str_pad, rhs, rhs_pad);

        keys.assert_to_lowercase(str, str_pad);
        keys.assert_to_uppercase(str, str_pad);

        keys.assert_concat(str, str_pad, rhs, rhs_pad);
        keys.assert_repeat(str, str_pad, n, max);

        keys.assert_trim_end(str, str_pad);
        keys.assert_trim_start(str, str_pad);
        keys.assert_trim(str, str_pad);
        keys.assert_split_ascii_whitespace(str, str_pad);

        keys.assert_split_once(str, str_pad, pat, pat_pad);
        keys.assert_rsplit_once(str, str_pad, pat, pat_pad);

        keys.assert_split(str, str_pad, pat, pat_pad);
        keys.assert_rsplit(str, str_pad, pat, pat_pad);

        keys.assert_split_terminator(str, str_pad, pat, pat_pad);
        keys.assert_rsplit_terminator(str, str_pad, pat, pat_pad);
        keys.assert_split_inclusive(str, str_pad, pat, pat_pad);

        keys.assert_splitn(str, str_pad, pat, pat_pad, n, max);
        keys.assert_rsplitn(str, str_pad, pat, pat_pad, n, max);

        keys.assert_replace(str, str_pad, pat, pat_pad, to, to_pad);
        keys.assert_replacen((str, str_pad), (pat, pat_pad), (to, to_pad), n, max);
    }

    pub(crate) struct Keys {
        pub(crate) ck: ClientKey,
        pub(crate) sk: ServerKey,
    }

    impl Keys {
        pub(crate) fn new(params: ClassicPBSParameters) -> Self {
            let (ck, sk) = KEY_CACHE.get_from_params(params, crate::integer::IntegerKeyKind::Radix);

            Self { ck, sk }
        }
    }
}
