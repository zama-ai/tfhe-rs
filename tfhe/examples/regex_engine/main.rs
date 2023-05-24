#[macro_use]
extern crate log;

mod ciphertext;
mod engine;
mod execution;
mod parser;

use env_logger::Env;
use std::env;

fn main() {
    let env = Env::default().filter_or("RUST_LOG", "info");
    env_logger::init_from_env(env);

    let args: Vec<String> = env::args().collect();
    let content = &args[1];
    let pattern = &args[2];

    let (client_key, server_key) = ciphertext::gen_keys();
    let ct_content = ciphertext::encrypt_str(&client_key, content).unwrap();

    let ct_res = engine::has_match(&server_key, &ct_content, pattern).unwrap();
    let res: u64 = client_key.decrypt(&ct_res);
    if res == 0 {
        println!("no match");
    } else {
        println!("match");
    }
}
