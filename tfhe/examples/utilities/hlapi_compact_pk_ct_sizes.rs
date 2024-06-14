#[path = "../../benches/utilities.rs"]
mod utilities;

use crate::utilities::{write_to_json, OperatorType};
use rand::Rng;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use tfhe::integer::U256;
use tfhe::keycache::NamedParam;
use tfhe::prelude::*;
use tfhe::shortint::parameters::classic::compact_pk::{
    PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS, PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS,
};
use tfhe::shortint::PBSParameters;
use tfhe::{
    generate_keys, CompactCiphertextList, CompactPublicKey, ConfigBuilder, FheUint256, FheUint32,
};

fn write_result(file: &mut File, name: &str, value: usize) {
    let line = format!("{name},{value}\n");
    let error_message = format!("cannot write {name} result into file");
    file.write_all(line.as_bytes()).expect(&error_message);
}

pub fn cpk_and_cctl_sizes(results_file: &Path) {
    const NB_CTXT: usize = 5;

    let mut rng = rand::thread_rng();

    File::create(results_file).expect("create results file failed");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(results_file)
        .expect("cannot open results file");

    let operator = OperatorType::Atomic;

    {
        let params = PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS;
        let config = ConfigBuilder::default()
            .use_custom_parameters(params, None, None)
            .build();
        let (client_key, _) = generate_keys(config);
        let test_name = format!("hlapi_sizes_{}_cpk", params.name());

        let params: PBSParameters = params.into();

        println!("Sizes for: {} and 32 bits", params.name());

        let public_key = CompactPublicKey::new(&client_key);

        let cpk_size = bincode::serialize(&public_key).unwrap().len();

        println!("PK size: {cpk_size} bytes");
        write_result(&mut file, &test_name, cpk_size);
        write_to_json::<u64, _>(
            &test_name,
            params,
            params.name(),
            "CPK",
            &operator,
            0,
            vec![],
        );

        let test_name = format!("hlapi_sizes_{}_cctl_{NB_CTXT}_len_32_bits", params.name());

        let vec_inputs: Vec<_> = (0..NB_CTXT).map(|_| rng.gen::<u32>()).collect();

        let encrypted_inputs = CompactCiphertextList::builder(&public_key)
            .extend(vec_inputs.iter().copied())
            .build();
        let cctl_size = bincode::serialize(&encrypted_inputs).unwrap().len();

        println!("Compact CT list for {NB_CTXT} CTs: {} bytes", cctl_size);

        write_result(&mut file, &test_name, cctl_size);
        write_to_json::<u64, _>(
            &test_name,
            params,
            params.name(),
            "CCTL",
            &operator,
            0,
            vec![],
        );

        let expander = encrypted_inputs.expand().unwrap();
        for (i, input) in vec_inputs.into_iter().enumerate() {
            let expanded: FheUint32 = expander.get(i).unwrap().unwrap();
            let clear: u32 = expanded.decrypt(&client_key);
            assert_eq!(clear, input);
        }
    }

    {
        let params = PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS;
        let config = ConfigBuilder::default()
            .use_custom_parameters(params, None, None)
            .build();
        let (client_key, _) = generate_keys(config);
        let test_name = format!("hlapi_sizes_{}_cpk", params.name());

        let params: PBSParameters = params.into();

        println!("Sizes for: {} and 32 bits", params.name());

        let public_key = CompactPublicKey::new(&client_key);

        let cpk_size = bincode::serialize(&public_key).unwrap().len();

        println!("PK size: {cpk_size} bytes");
        write_result(&mut file, &test_name, cpk_size);
        write_to_json::<u64, _>(
            &test_name,
            params,
            params.name(),
            "CPK",
            &operator,
            0,
            vec![],
        );

        let test_name = format!("hlapi_sizes_{}_cctl_{NB_CTXT}_len_32_bits", params.name());

        let vec_inputs: Vec<_> = (0..NB_CTXT).map(|_| rng.gen::<u32>()).collect();

        let encrypted_inputs = CompactCiphertextList::builder(&public_key)
            .extend(vec_inputs.iter().copied())
            .build();
        let cctl_size = bincode::serialize(&encrypted_inputs).unwrap().len();

        println!("Compact CT list for {NB_CTXT} CTs: {} bytes", cctl_size);

        write_result(&mut file, &test_name, cctl_size);
        write_to_json::<u64, _>(
            &test_name,
            params,
            params.name(),
            "CCTL",
            &operator,
            0,
            vec![],
        );

        let expander = encrypted_inputs.expand().unwrap();
        for (i, input) in vec_inputs.into_iter().enumerate() {
            let expanded: FheUint32 = expander.get(i).unwrap().unwrap();
            let clear: u32 = expanded.decrypt(&client_key);
            assert_eq!(clear, input);
        }
    }

    // 256 bits
    {
        let params = PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_KS_PBS;
        let config = ConfigBuilder::default()
            .use_custom_parameters(params, None, None)
            .build();
        let (client_key, _) = generate_keys(config);

        let params: PBSParameters = params.into();

        println!("Sizes for: {} and 256 bits", params.name());

        let public_key = CompactPublicKey::new(&client_key);

        println!(
            "PK size: {} bytes",
            bincode::serialize(&public_key).unwrap().len()
        );

        let test_name = format!("hlapi_sizes_{}_cctl_{NB_CTXT}_len_256_bits", params.name());

        let vec_inputs: Vec<_> = (0..NB_CTXT).map(|_| U256::from(rng.gen::<u32>())).collect();

        let encrypted_inputs = CompactCiphertextList::builder(&public_key)
            .extend(vec_inputs.iter().copied())
            .build();
        let cctl_size = bincode::serialize(&encrypted_inputs).unwrap().len();

        println!("Compact CT list for {NB_CTXT} CTs: {} bytes", cctl_size);

        write_result(&mut file, &test_name, cctl_size);
        write_to_json::<u64, _>(
            &test_name,
            params,
            params.name(),
            "CCTL",
            &operator,
            0,
            vec![],
        );

        let expander = encrypted_inputs.expand().unwrap();
        for (i, input) in vec_inputs.into_iter().enumerate() {
            let expanded: FheUint256 = expander.get(i).unwrap().unwrap();
            let clear: U256 = expanded.decrypt(&client_key);
            assert_eq!(clear, input);
        }
    }

    {
        let params = PARAM_MESSAGE_2_CARRY_2_COMPACT_PK_PBS_KS;
        let config = ConfigBuilder::default()
            .use_custom_parameters(params, None, None)
            .build();
        let (client_key, _) = generate_keys(config);

        let params: PBSParameters = params.into();

        println!("Sizes for: {} and 256 bits", params.name());

        let public_key = CompactPublicKey::new(&client_key);

        println!(
            "PK size: {} bytes",
            bincode::serialize(&public_key).unwrap().len()
        );

        let test_name = format!("hlapi_sizes_{}_cctl_{NB_CTXT}_len_256_bits", params.name());

        let vec_inputs: Vec<_> = (0..NB_CTXT).map(|_| U256::from(rng.gen::<u32>())).collect();

        let encrypted_inputs = CompactCiphertextList::builder(&public_key)
            .extend(vec_inputs.iter().copied())
            .build();
        let cctl_size = bincode::serialize(&encrypted_inputs).unwrap().len();

        println!("Compact CT list for {NB_CTXT} CTs: {} bytes", cctl_size);

        write_result(&mut file, &test_name, cctl_size);
        write_to_json::<u64, _>(
            &test_name,
            params,
            params.name(),
            "CCTL",
            &operator,
            0,
            vec![],
        );

        let expander = encrypted_inputs.expand().unwrap();
        for (i, input) in vec_inputs.into_iter().enumerate() {
            let expanded: FheUint256 = expander.get(i).unwrap().unwrap();
            let clear: U256 = expanded.decrypt(&client_key);
            assert_eq!(clear, input);
        }
    }
}

fn main() {
    let work_dir = std::env::current_dir().unwrap();
    println!("work_dir: {}", std::env::current_dir().unwrap().display());
    // Change workdir so that the location of the keycache matches the one for tests
    let mut new_work_dir = work_dir;
    new_work_dir.push("tfhe");
    std::env::set_current_dir(new_work_dir).unwrap();

    let results_file = Path::new("hlapi_cpk_and_cctl_sizes.csv");
    cpk_and_cctl_sizes(results_file)
}
