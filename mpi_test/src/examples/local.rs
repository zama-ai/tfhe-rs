use crate::context::Context;
use std::time::Instant;
use tfhe::shortint::gen_keys;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

fn local() {
    const N: u64 = 1;

    let (cks, sks) = gen_keys(PARAM_MESSAGE_2_CARRY_2_KS_PBS);

    let mut inputs = vec![];

    for i in 0..N {
        let ct = cks.unchecked_encrypt(i % 16);

        inputs.push(ct);
    }

    let lookup_table = sks.generate_lookup_table(|x| (x + 1) % 16);

    let start = Instant::now();

    let _outputs: Vec<_> = inputs
        .iter()
        // .par_iter()
        .map(|ct| sks.apply_lookup_table(ct, &lookup_table))
        .collect();

    let duration = start.elapsed();

    let duration_sec = duration.as_secs_f32();

    println!("{N} PBS in {}s", duration_sec);
    println!("{} ms/PBS", duration_sec * 1000. / N as f32);
}

fn local_mul(num_blocks: usize) {
    use tfhe::integer::gen_keys_radix;

    // Generate the client key and the server key:
    let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, num_blocks);

    let clear_1: u64 = 255;
    let clear_2: u64 = 143;

    // Encrypt two messages
    let ctxt_1 = cks.encrypt(clear_1);
    let ctxt_2 = cks.encrypt(clear_2);

    let start = Instant::now();

    // Compute homomorphically a multiplication
    let _ct_res = sks.unchecked_mul_parallelized(&ctxt_1, &ctxt_2);

    let duration = start.elapsed();

    let duration_sec = duration.as_secs_f32();

    // Decrypt
    // let res: u64 = cks.decrypt(&ct_res);
    // assert_eq!((clear_1 * clear_2) % 256, res);

    println!("{num_blocks} block mul in {}s", duration_sec);
}

impl Context {
    pub fn run_local_on_root(&self) {
        if self.is_root {
            local();
        }
    }

    pub fn run_local_mul_on_root(&self, num_blocks: usize) {
        if self.is_root {
            local_mul(num_blocks);
        }
    }
}
