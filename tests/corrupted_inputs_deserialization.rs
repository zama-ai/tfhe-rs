//! This test tries to load various kind of corrupted serialized inputs and see that they are
//! handled without crashes.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use tfhe::conformance::ListSizeConstraint;
use tfhe::integer::ciphertext::IntegerProvenCompactCiphertextListConformanceParams;
use tfhe::prelude::CiphertextList;
use tfhe::safe_serialization::{safe_deserialize, safe_deserialize_conformant};
use tfhe::zk::CompactPkeCrs;
use tfhe::{
    set_server_key, CompactCiphertextList, CompactCiphertextListConformanceParams,
    CompactCiphertextListExpander, CompactPublicKey, FheInt16, FheInt32, FheInt64, FheInt8,
    FheTypes, FheUint16, FheUint32, FheUint64, FheUint8, ProvenCompactCiphertextList, ServerKey,
};

const DATA_DIR: &str = "./corrupted_inputs_deserialization/data";
const AUX_DIR: &str = "aux_data";
const GIGA: u64 = 1024 * 1024 * 1024;

fn load_server_key(aux_dir: &Path) -> ServerKey {
    let path = aux_dir.join("server_key.bcode");
    let f = File::open(&path).unwrap_or_else(|e| panic!("failed to open {}: {e}", path.display()));
    safe_deserialize(f, 4 * GIGA).unwrap()
}

fn load_crs(aux_dir: &Path) -> CompactPkeCrs {
    let path = aux_dir.join("crs.bcode");
    let f = File::open(&path).unwrap_or_else(|e| panic!("failed to open {}: {e}", path.display()));
    safe_deserialize(f, 4 * GIGA).unwrap()
}

fn load_public_key(aux_dir: &Path) -> CompactPublicKey {
    let path = aux_dir.join("pubkey.bcode");
    let f = File::open(&path).unwrap_or_else(|e| panic!("failed to open {}: {e}", path.display()));
    safe_deserialize(f, 4 * GIGA).unwrap()
}

fn load_metadata(aux_dir: &Path) -> Vec<u8> {
    let path = aux_dir.join("metadata.txt");
    std::fs::read(&path).unwrap_or_else(|e| panic!("failed to open {}: {e}", path.display()))
}

fn list_subdirs(dir: &Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", dir.display()))
        .filter_map(|entry| {
            let entry = entry.unwrap();
            entry.file_type().unwrap().is_dir().then(|| entry.path())
        })
        .collect()
}

/// Read all .bcode files in `dir` and call `handler` on each file.
fn process_inputs(dir: &Path, mut handler: impl FnMut(&[u8])) -> u64 {
    let mut total_tests = 0;
    let entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", dir.display()))
        .collect::<Result<_, _>>()
        .unwrap();

    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("bcode") {
            println!("Processing {}", path.display());
            total_tests += 1;
            let mut input = Vec::new();
            File::open(&path)
                .unwrap_or_else(|e| panic!("failed to open {}: {e}", path.display()))
                .read_to_end(&mut input)
                .unwrap();
            handler(&input);
        }
    }

    total_tests
}

macro_rules! test_type {
    ($exp:expr, $i:expr, $T:ty) => {{
        let Ok(Some(ct)) = $exp.get::<$T>($i) else {
            return;
        };
        let res = ct.clone() + ct.clone();
        let res = res * ct.clone();
        let _ = std::hint::black_box(res - ct);
    }};
}

/// Try to expand each element and perform some operations, dispatching on the
/// actual type reported by the expander.
fn use_list(exp: &CompactCiphertextListExpander) {
    for i in 0..exp.len() {
        let Some(kind) = exp.get_kind_of(i) else {
            return;
        };

        match kind {
            FheTypes::Uint8 => test_type!(exp, i, FheUint8),
            FheTypes::Uint16 => test_type!(exp, i, FheUint16),
            FheTypes::Uint32 => test_type!(exp, i, FheUint32),
            FheTypes::Uint64 => test_type!(exp, i, FheUint64),
            FheTypes::Int8 => test_type!(exp, i, FheInt8),
            FheTypes::Int16 => test_type!(exp, i, FheInt16),
            FheTypes::Int32 => test_type!(exp, i, FheInt32),
            FheTypes::Int64 => test_type!(exp, i, FheInt64),
            other => panic!(
                "unsupported FheTypes variant {other:?} at index {i}, \
                 this test should be updated to handle it"
            ),
        }
    }
}

fn handle_ct_list(input: &[u8], conformance_params: &CompactCiphertextListConformanceParams) {
    let ct_list: CompactCiphertextList = match safe_deserialize_conformant::<CompactCiphertextList>(
        input,
        4 * GIGA,
        conformance_params,
    ) {
        Ok(ct_list) => ct_list,
        Err(e) => {
            println!("Error caught during deserialization:\n{e}\n");
            return;
        }
    };

    let exp = match ct_list.expand() {
        Ok(exp) => exp,
        Err(e) => {
            println!("Error caught during expand:\n{e}\n");
            return;
        }
    };

    use_list(&exp);
    println!("List used without error\n")
}

fn handle_proven_ct_list(
    input: &[u8],
    conformance_params: &IntegerProvenCompactCiphertextListConformanceParams,
    crs: &CompactPkeCrs,
    public_key: &CompactPublicKey,
    metadata: &[u8],
) {
    let ct_list: ProvenCompactCiphertextList = match safe_deserialize_conformant::<
        ProvenCompactCiphertextList,
    >(input, 4 * GIGA, conformance_params)
    {
        Ok(ct_list) => ct_list,
        Err(e) => {
            println!("Error caught during deserialization:\n{e}\n");
            return;
        }
    };

    let exp = match ct_list.verify_and_expand(crs, public_key, metadata) {
        Ok(exp) => exp,
        Err(e) => {
            println!("Error caught during verify_and_expand:\n{e}\n");
            return;
        }
    };

    use_list(&exp);
    println!("List used without error\n")
}

#[test]
fn test_corrupted_inputs_deserialization() {
    let mut total_tests = 0;
    let data_dir = Path::new(DATA_DIR);

    let compact_list_dir = data_dir.join("compact_list");
    for group_dir in list_subdirs(&compact_list_dir) {
        println!("compact_list group: {}", group_dir.display());
        let aux_dir = group_dir.join(AUX_DIR);

        let server_key = load_server_key(&aux_dir);
        let pubkey = load_public_key(&aux_dir);

        let cpk_conformance_params =
            CompactCiphertextListConformanceParams::from_parameters_and_size_constraint(
                pubkey.parameters(),
                ListSizeConstraint::try_size_in_range(4, usize::MAX).unwrap(),
            )
            .allow_unpacked();

        set_server_key(server_key);

        total_tests += process_inputs(&group_dir, |input| {
            handle_ct_list(input, &cpk_conformance_params);
        });
    }

    let proven_compact_list_dir = data_dir.join("proven_compact_list");
    for group_dir in list_subdirs(&proven_compact_list_dir) {
        println!("proven_compact_list group: {}", group_dir.display());
        let aux_dir = group_dir.join(AUX_DIR);

        let server_key = load_server_key(&aux_dir);
        let pubkey = load_public_key(&aux_dir);
        let crs = load_crs(&aux_dir);
        let metadata = load_metadata(&aux_dir);

        let proven_cpk_conformance_params =
            IntegerProvenCompactCiphertextListConformanceParams::from_public_key_encryption_parameters_and_crs_parameters(
                pubkey.parameters(),
                &crs,
            )
            .allow_unpacked();

        set_server_key(server_key);

        total_tests += process_inputs(&group_dir, |input| {
            handle_proven_ct_list(
                input,
                &proven_cpk_conformance_params,
                &crs,
                &pubkey,
                &metadata,
            );
        });
    }

    println!("Executed {} tests", total_tests);
    // If we ran 0 test, it is likely that something wrong happened
    assert!(total_tests != 0);
}
