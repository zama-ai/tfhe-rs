use crate::ciphertext::{FheString, UIntArg};
use crate::client_key::ClientKey;
use crate::server_key::{gen_keys, FheStringIsEmpty, FheStringIterator, FheStringLen, ServerKey};
use clap::{value_parser, Arg, Command};
use std::time::Instant;

mod ciphertext;
mod client_key;
mod server_key;

mod assert_functions;

// Used as the const argument for StaticUnsignedBigInt, specifying the max u64 length of a
// ClearString
const N: usize = 4;

fn main() {
    let matches = Command::new("FHE str API")
        .arg(
            Arg::new("string")
                .long("str")
                .help("str that will be used for the functions")
                .allow_hyphen_values(true)
                .required(true)
        )
        .arg(
            Arg::new("string_padding")
                .long("str_pad")
                .help("the number of padding nulls to use in str")
                .value_parser(value_parser!(u32))
        )
        .arg(
            Arg::new("pattern")
                .long("pat")
                .help("pat that will be used for the functions")
                .allow_hyphen_values(true)
                .required(true)
        )
        .arg(
            Arg::new("pattern_padding")
                .long("pat_pad")
                .help("the number of padding nulls to use in pat")
                .value_parser(value_parser!(u32))
        )
        .arg(
            Arg::new("to")
                .long("to")
                .help("the argument used to replace the pattern in `replace` and `replacen`")
                .allow_hyphen_values(true)
                .required(true)
        )
        .arg(
            Arg::new("to_padding")
                .long("to_pad")
                .help("The number of padding nulls to use in to")
                .value_parser(value_parser!(u32))
        )
        .arg(
            Arg::new("rhs")
                .long("rhs")
                .help("The right side string used in `concat` and all comparisons")
                .allow_hyphen_values(true)
                .required(true)
        )
        .arg(
            Arg::new("rhs_padding")
                .long("rhs_pad")
                .help("The number of padding nulls to use in rhs")
                .value_parser(value_parser!(u32))
        )
        .arg(
            Arg::new("count")
                .long("n")
                .help("The count number that will be used in some functions like `replacen` and `splitn`")
                .value_parser(value_parser!(u16))
                .required(true)
        )
        .arg(
            Arg::new("max_count")
                .long("max")
                .help("The max number that the n argument can take (useful for when n is encrypted, \
                as we need a worst case scenario of how many times we will repeat something)")
                .value_parser(value_parser!(u16))
                .required(true)
        )
        .get_matches();

    let str = matches.get_one::<String>("string").unwrap();
    let str_pad = matches.get_one("string_padding").copied();

    let pat = matches.get_one::<String>("pattern").unwrap();
    let pat_pad = matches.get_one("pattern_padding").copied();

    let to = matches.get_one::<String>("to").unwrap();
    let to_pad: Option<u32> = matches.get_one("to_padding").copied();

    let rhs = matches.get_one::<String>("rhs").unwrap();
    let rhs_pad = matches.get_one("rhs_padding").copied();

    let n: u16 = matches.get_one("count").copied().unwrap();
    let max: u16 = matches.get_one("max_count").copied().unwrap();

    let keys = Keys::new();

    keys.assert_len(str, str_pad);
    keys.assert_is_empty(str, str_pad);

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

struct Keys {
    ck: ClientKey,
    sk: ServerKey,
}

impl Keys {
    fn new() -> Self {
        let (ck, sk) = gen_keys();

        Keys { ck, sk }
    }
}
