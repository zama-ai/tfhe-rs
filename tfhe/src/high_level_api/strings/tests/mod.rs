use crate::prelude::*;
use crate::{ClearString, ClientKey, FheAsciiString, FheStringIsEmpty, FheStringLen};

mod cpu;

fn test_string_eq_ne(client_key: &ClientKey) {
    let string1 = FheAsciiString::try_encrypt("Zama", client_key).unwrap();
    let string2 = FheAsciiString::try_encrypt("zama", client_key).unwrap();

    assert!(!string1.eq(&string2).decrypt(client_key));
    assert!(!string1
        .eq(&ClearString::new("zamA".into()))
        .decrypt(client_key));

    assert!(string1.eq(&string1).decrypt(client_key));
    assert!(string2.eq(&string2).decrypt(client_key));

    assert!(string1.ne(&string2).decrypt(client_key));

    assert!(!string1.ne(&string1).decrypt(client_key));
    assert!(!string2.ne(&string2).decrypt(client_key));
}

fn test_string_find_rfind(client_key: &ClientKey) {
    // Simple case with no duplicate
    {
        let clear_string = "The quick brown fox jumps over the lazy dog";
        let string1 = FheAsciiString::try_encrypt(clear_string, client_key).unwrap();

        let (index, found) = string1.find(&ClearString::new("brown".into()));
        assert!(found.decrypt(client_key));
        let index: u32 = index.decrypt(client_key);
        assert_eq!(index as usize, clear_string.find("brown").unwrap());

        let (index, found) = string1.find(&ClearString::new("cat".into()));
        assert!(!found.decrypt(client_key));
        let index: u32 = index.decrypt(client_key);
        assert_eq!(index as usize, 0);
    }

    {
        let clear_string = "The quick brown dog jumps over the lazy dog";
        let string1 = FheAsciiString::try_encrypt(clear_string, client_key).unwrap();

        let (index, found) = string1.find(&ClearString::new("dog".into()));
        assert!(found.decrypt(client_key));
        let index: u32 = index.decrypt(client_key);
        assert_eq!(index as usize, clear_string.find("dog").unwrap());

        let (index, found) = string1.rfind(&ClearString::new("dog".into()));
        assert!(found.decrypt(client_key));
        let index: u32 = index.decrypt(client_key);
        assert_eq!(index as usize, clear_string.rfind("dog").unwrap());
    }
}

fn test_string_len_is_empty(client_key: &ClientKey) {
    let clear_string = "The quick brown fox jumps over the lazy dog";
    let string = FheAsciiString::try_encrypt(clear_string, client_key).unwrap();
    match string.len() {
        FheStringLen::NoPadding(len) => assert_eq!(len, clear_string.len() as u16),
        FheStringLen::Padding(_) => {
            panic!("Unexpected result");
        }
    }
    match string.is_empty() {
        FheStringIsEmpty::NoPadding(is_empty) => {
            assert!(!is_empty);
        }
        FheStringIsEmpty::Padding(_) => {
            panic!("Unexpected result");
        }
    }

    let padding_len = 10;
    let string =
        FheAsciiString::try_encrypt_with_padding(clear_string, padding_len, client_key).unwrap();
    match string.len() {
        FheStringLen::NoPadding(_) => panic!("Unexpected result"),
        FheStringLen::Padding(enc_len) => {
            let len: u16 = enc_len.decrypt(client_key);
            assert_eq!(len, clear_string.len() as u16)
        }
    }
    match string.is_empty() {
        FheStringIsEmpty::NoPadding(_) => {
            panic!("Unexpected result");
        }
        FheStringIsEmpty::Padding(enc_is_empty) => {
            let is_empty = enc_is_empty.decrypt(client_key);
            assert!(!is_empty);
        }
    }

    let string = FheAsciiString::try_encrypt("", client_key).unwrap();
    match string.len() {
        FheStringLen::NoPadding(len) => assert_eq!(len, 0u16),
        FheStringLen::Padding(_) => {
            panic!("Unexpected result");
        }
    }
    match string.is_empty() {
        FheStringIsEmpty::NoPadding(is_empty) => {
            assert!(is_empty);
        }
        FheStringIsEmpty::Padding(_) => {
            panic!("Unexpected result");
        }
    }

    let string = FheAsciiString::try_encrypt_with_padding("", 10, client_key).unwrap();
    match string.len() {
        FheStringLen::NoPadding(_) => panic!("Unexpected result"),
        FheStringLen::Padding(r) => {
            let len: u16 = r.decrypt(client_key);
            assert_eq!(len, 0);
        }
    }
    match string.is_empty() {
        FheStringIsEmpty::NoPadding(_) => {
            panic!("Unexpected result")
        }
        FheStringIsEmpty::Padding(r) => {
            assert!(r.decrypt(client_key));
        }
    }
}

fn test_string_lower_upper(client_key: &ClientKey) {
    let string = FheAsciiString::try_encrypt("12TfHe3-8RS!@", client_key).unwrap();

    let lower = string.to_lowercase();
    let dec = lower.decrypt(client_key);
    assert_eq!(&dec, "12tfhe3-8rs!@");

    let upper = string.to_uppercase();
    let dec = upper.decrypt(client_key);
    assert_eq!(&dec, "12TFHE3-8RS!@");
}

fn test_string_trim(client_key: &ClientKey) {
    let string = FheAsciiString::try_encrypt("   tfhe-rs   zama   ", client_key).unwrap();

    let trimmed_start = string.trim_start();
    let dec = trimmed_start.decrypt(client_key);
    assert_eq!(dec, "tfhe-rs   zama   ");

    let trimmed_end = string.trim_end();
    let dec = trimmed_end.decrypt(client_key);
    assert_eq!(dec, "   tfhe-rs   zama");

    let trimmed = string.trim();
    let dec = trimmed.decrypt(client_key);
    assert_eq!(dec, "tfhe-rs   zama");
}

fn test_string_strip(client_key: &ClientKey) {
    let string = FheAsciiString::try_encrypt("The lazy cat", client_key).unwrap();

    let prefix = FheAsciiString::try_encrypt("The", client_key).unwrap();
    let (stripped, is_stripped) = string.strip_prefix(&prefix);
    assert!(is_stripped.decrypt(client_key));
    let dec = stripped.decrypt(client_key);
    assert_eq!(dec, " lazy cat");

    let prefix = FheAsciiString::try_encrypt("the", client_key).unwrap();
    let (stripped, is_stripped) = string.strip_prefix(&prefix);
    assert!(!is_stripped.decrypt(client_key));
    let dec = stripped.decrypt(client_key);
    assert_eq!(dec, "The lazy cat");

    let prefix = ClearString::new("cat".into());
    let (stripped, is_stripped) = string.strip_suffix(&prefix);
    assert!(is_stripped.decrypt(client_key));
    let dec = stripped.decrypt(client_key);
    assert_eq!(dec, "The lazy ");

    let prefix = ClearString::new("dog".into());
    let (stripped, is_stripped) = string.strip_suffix(&prefix);
    assert!(!is_stripped.decrypt(client_key));
    let dec = stripped.decrypt(client_key);
    assert_eq!(dec, "The lazy cat");
}
