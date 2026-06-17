use std::env;
use std::path::Path;
use std::process::exit;

use forward_common::{
    load, report, write_artifact, ARTIFACTS, CLEAR_BOOL, CLEAR_U32, CLEAR_U8, PROVEN_LEN,
    ZK_METADATA,
};

use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe::shortint::parameters::{
    PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
    PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
};
use tfhe::zk::{CompactPkeCrs, ZkComputeLoad};
use tfhe::{ClientKey, CompactPublicKey, ConfigBuilder, ProvenCompactCiphertextList};

fn produce(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();

    let config =
        ConfigBuilder::with_custom_parameters(PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128)
            .use_dedicated_compact_public_key_parameters((
                PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
                PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128,
            ))
            .build();
    let ck = ClientKey::generate(config);
    let crs = CompactPkeCrs::from_config(config, 64).unwrap();
    let cpk = CompactPublicKey::try_new(&ck).unwrap();
    let proven = ProvenCompactCiphertextList::builder(&cpk)
        .push(CLEAR_BOOL)
        .push(CLEAR_U8)
        .push(CLEAR_U32)
        .build_with_proof_packed(&crs, ZK_METADATA, ZkComputeLoad::Verify)
        .unwrap();

    write_artifact!(dir, "CompactPublicKey", cpk);
    write_artifact!(dir, "CompactPkeCrs", crs);
    write_artifact!(dir, "ProvenCompactCiphertextList", proven);

    eprintln!(
        "produced {} artifacts in {}",
        ARTIFACTS.len(),
        dir.display()
    );
}

fn check_proven(res: Result<ProvenCompactCiphertextList, String>) -> Result<(), String> {
    let pl = res?;
    if pl.len() != PROVEN_LEN {
        return Err(format!("len {} != {PROVEN_LEN}", pl.len()));
    }
    for i in 0..pl.len() {
        if pl.get_kind_of(i).is_none() {
            return Err(format!("get_kind_of({i}) = None"));
        }
    }
    Ok(())
}

fn consume(dir: &Path) {
    report(
        "CompactPublicKey",
        load!(dir, "CompactPublicKey", CompactPublicKey).map(|_| ()),
    );
    report(
        "CompactPkeCrs",
        load!(dir, "CompactPkeCrs", CompactPkeCrs).map(|_| ()),
    );
    report(
        "ProvenCompactCiphertextList",
        check_proven(load!(
            dir,
            "ProvenCompactCiphertextList",
            ProvenCompactCiphertextList
        )),
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: {} <produce|consume> <dir>", args[0]);
        exit(2);
    }
    let dir = Path::new(&args[2]);
    match args[1].as_str() {
        "produce" => produce(dir),
        "consume" => consume(dir),
        other => {
            eprintln!("unknown command: {other}");
            exit(2);
        }
    }
}
