use crate::float_wopbs::{ClientKey, ServerKey};
use crate::shortint::WopbsParameters;
use lazy_static::lazy_static;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;

#[derive(Default)]
pub struct FloatKeyCache;

const FLOAT_KEY_DIR: &str = "../keys/float/";

impl FloatKeyCache {
    pub fn get_from_params(&self, wopbs_params: WopbsParameters) -> (ClientKey, ServerKey) {
        let pbs_params = crate::shortint::parameters::ClassicPBSParameters {
            lwe_dimension: wopbs_params.lwe_dimension,
            glwe_dimension: wopbs_params.glwe_dimension,
            polynomial_size: wopbs_params.polynomial_size,
            lwe_modular_std_dev: wopbs_params.lwe_modular_std_dev,
            glwe_modular_std_dev: wopbs_params.glwe_modular_std_dev,
            pbs_base_log: wopbs_params.pbs_base_log,
            pbs_level: wopbs_params.pbs_level,
            ks_base_log: wopbs_params.ks_base_log,
            ks_level: wopbs_params.ks_level,
            message_modulus: wopbs_params.message_modulus,
            carry_modulus: wopbs_params.carry_modulus,
            ciphertext_modulus: wopbs_params.ciphertext_modulus,
            encryption_key_choice: wopbs_params.encryption_key_choice,
        };

        let params = (pbs_params, wopbs_params);

        let keys = crate::shortint::keycache::KEY_CACHE_WOPBS.get_from_param(params);
        let (client_key, server_key) = (keys.client_key(), keys.server_key());
        // TODO DANGER
        let wopbs_key =
            crate::shortint::wopbs::WopbsKey::new_wopbs_key_only_for_wopbs(client_key, server_key);
        let client_key = ClientKey::from_shortint(client_key.clone());
        let server_key = ServerKey::from_shortint(&client_key, server_key.clone(), wopbs_key);
        (client_key, server_key)
    }
}

lazy_static! {
    pub static ref KEY_CACHE: FloatKeyCache = FloatKeyCache::default();
}

pub fn get_sks(str: &str) -> Option<ServerKey> {
    let fiptr = format!("{}SKS_{}.bin", FLOAT_KEY_DIR,str);
    let filepath = Path::new(&fiptr);
    let file = File::open(filepath);
    let file = match file {
        Ok(file) => file,
        Err(_) => return None,
    };
    let file = BufReader::new(file);
    let saved_key: ServerKey = bincode::deserialize_from(file).unwrap();
    Some(saved_key)
}

pub fn get_cks(str: &str) -> Option<ClientKey> {
    let fiptr = format!("{}CKS_{}.bin", FLOAT_KEY_DIR,str);
    let filepath = Path::new(&fiptr);
    let file = File::open(filepath);
    let file = match file {
        Ok(file) => file,
        Err(_) => return None,
    };
    let file = BufReader::new(file);
    let saved_key: ClientKey = bincode::deserialize_from(file).unwrap();
    Some(saved_key)
}

pub fn save_sks(key: &ServerKey, str: &str) {
    let filepath = format!("{}SKS_{}.bin", FLOAT_KEY_DIR,str);
    std::fs::create_dir_all(FLOAT_KEY_DIR).unwrap();
    let file = BufWriter::new(File::create(filepath).unwrap());
    bincode::serialize_into(file, key).unwrap();
}

pub fn save_cks(key: &ClientKey, str: &str) {
    let filepath = format!("{}CKS_{}.bin", FLOAT_KEY_DIR,str);
    std::fs::create_dir_all(FLOAT_KEY_DIR).unwrap();
    let file = BufWriter::new(File::create(filepath).unwrap());
    bincode::serialize_into(file, key).unwrap();
}
