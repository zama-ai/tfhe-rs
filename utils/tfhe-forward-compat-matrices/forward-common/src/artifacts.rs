//! What every per-version binary writes, and reads back.

/// Ceiling given to the safe serialization, generous enough for a public key.
pub const LIMIT: u64 = 1 << 30;
pub const CLEAR_U8: u8 = 42;
pub const CLEAR_U32: u32 = 0xDEADBEEF;
pub const CLEAR_BOOL: bool = true;
pub const PROVEN_LEN: usize = 3;
pub const ZK_METADATA: &[u8] = b"fwd-compat";

pub struct Artifact {
    pub name: &'static str,
    pub file: &'static str,
}

pub const ARTIFACTS: [Artifact; 3] = [
    Artifact {
        name: "CompactPublicKey",
        file: "compact_public_key.bin",
    },
    Artifact {
        name: "CompactPkeCrs",
        file: "compact_pke_crs.bin",
    },
    Artifact {
        name: "ProvenCompactCiphertextList",
        file: "proven_compact_list.bin",
    },
];

pub fn file_of(name: &str) -> &'static str {
    ARTIFACTS
        .iter()
        .find(|a| a.name == name)
        .unwrap_or_else(|| panic!("unknown artifact {name:?}"))
        .file
}

/// Serialize `$val` into the file registered for `$name`.
/// `safe_serialize` is resolved at the call site (the per-version tfhe).
#[macro_export]
macro_rules! write_artifact {
    ($dir:expr, $name:expr, $val:expr) => {{
        let mut bytes = ::std::vec::Vec::new();
        ::tfhe::safe_serialization::safe_serialize(&$val, &mut bytes, $crate::LIMIT).unwrap();
        ::std::fs::write($dir.join($crate::file_of($name)), &bytes).unwrap();
    }};
}

/// Deserialize the file registered for `$name` as `$ty` -> `Result<$ty, String>`.
/// `safe_deserialize` is resolved at the call site (the per-version tfhe).
#[macro_export]
macro_rules! load {
    ($dir:expr, $name:expr, $ty:ty) => {
        ::std::fs::read($dir.join($crate::file_of($name)))
            .map_err(|e| e.to_string())
            .and_then(|b| {
                ::tfhe::safe_serialization::safe_deserialize::<$ty>(b.as_slice(), $crate::LIMIT)
            })
    };
}
