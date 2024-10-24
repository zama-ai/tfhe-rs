pub mod ciphertext;
pub mod client_key;
pub mod server_key;

#[cfg(test)]
mod assert_functions;

// Used as the const argument for StaticUnsignedBigInt, specifying the max u64 length of a
// ClearString
const N: usize = 4;

#[cfg(test)]
pub(crate) use test::Keys;

#[cfg(test)]
mod test {
    use crate::integer::{ClientKey, ServerKey};
    use crate::shortint::prelude::PARAM_MESSAGE_2_CARRY_2;

    #[test]
    fn test_all2() {
        test_all("", Some(0), "", Some(0), "", Some(0), "", Some(0), 1, 1);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn test_all(
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
        let keys = Keys::new();

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
        pub(crate) fn new() -> Self {
            let ck = ClientKey::new(PARAM_MESSAGE_2_CARRY_2);
            let sk = ServerKey::new_radix_server_key(&ck);

            Self { ck, sk }
        }
    }
}
