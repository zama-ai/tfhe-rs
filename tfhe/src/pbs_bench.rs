use lamellar::ActiveMessaging;
use rand::Rng;
use std::time::Instant;
use tfhe::shortint::keycache::KEY_CACHE;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
use tfhe::shortint::{Ciphertext, DISPATCHER};

fn main() {
    let count = 10000;

    let keys = KEY_CACHE.get_from_param(PARAM_MESSAGE_2_CARRY_2_KS_PBS);
    let (cks, sks) = (keys.client_key(), keys.server_key());

    let mut rng = rand::thread_rng();

    let modulus = cks.parameters.message_modulus().0 as u64;

    let acc = sks.generate_lookup_table(|x| x);

    let clear_0 = rng.gen::<u64>() % modulus;

    let ctxt = cks.encrypt(clear_0);

    let before = Instant::now();

    let a: Vec<_> = (0..count)
        .map(|_| sks.apply_lookup_table_future(ctxt.clone(), acc.clone()))
        .collect();

    for i in a {
        let c: Ciphertext = DISPATCHER.world.block_on(i);
    }

    println!("{} PBS done in {}s", count, before.elapsed().as_secs());
}
