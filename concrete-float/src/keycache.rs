use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;
use lazy_static::lazy_static;

use crate::{ClientKey, ServerKey};

#[derive(Default)]
pub struct FloatKeyCache;

lazy_static! {
    pub static ref KEY_CACHE: FloatKeyCache = FloatKeyCache::default();
}

pub fn get_sks(str: &str) ->  ServerKey {
    let fiptr = format!("key/sks_key/{}", str);
    let filepath = Path::new(&fiptr);
    let file = BufReader::new(File::open(filepath).unwrap());
    let saved_key: ServerKey = bincode::deserialize_from(file).unwrap();
    saved_key
}

pub fn get_cks(str: &str) ->  ClientKey {
    let fiptr = format!("key/cks_key/{}", str);
    let filepath = Path::new(&fiptr);
    let file = BufReader::new(File::open(filepath).unwrap());
    let saved_key: ClientKey = bincode::deserialize_from(file).unwrap();
    saved_key
}

pub fn save_sks(key: ServerKey, str: &str) {
    let filepath = format!("key/sks_key/{}", str);
    let file = BufWriter::new(File::create(filepath).unwrap());
    bincode::serialize_into(file, &key).unwrap();
}

pub fn save_cks(key: ClientKey ,str: &str) {
    let filepath = format!("key/cks_key/{}", str);
    let file = BufWriter::new(File::create(filepath).unwrap());
    bincode::serialize_into(file, &key).unwrap();
}