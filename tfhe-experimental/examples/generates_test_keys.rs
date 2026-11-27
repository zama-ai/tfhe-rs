use tfhe_experimental::boolean::keycache::KEY_CACHE;
use tfhe_experimental::boolean::parameters::{
    BooleanParameters, DEFAULT_PARAMETERS, DEFAULT_PARAMETERS_KS_PBS,
};

fn generate_boolean_keys(params: &[BooleanParameters]) {
    println!("Generating boolean (ClientKey, ServerKey)");

    for (i, param) in params.iter().copied().enumerate() {
        println!("Generating [{} / {}]", i + 1, params.len());

        let start = std::time::Instant::now();

        let _ = KEY_CACHE.get_from_param(param);

        let stop = start.elapsed().as_secs();

        println!("Generation took {stop} seconds");

        // Clear keys as we go to avoid filling the RAM
        KEY_CACHE.clear_in_memory_cache()
    }
}

fn main() {
    let work_dir = std::env::current_dir().unwrap();
    println!("work_dir: {}", work_dir.display());
    // Change workdir so that the location of the keycache matches the one for tests
    let mut new_work_dir = work_dir;
    new_work_dir.push("tfhe-experimental");
    std::env::set_current_dir(new_work_dir).unwrap();

    generate_boolean_keys(&[DEFAULT_PARAMETERS, DEFAULT_PARAMETERS_KS_PBS]);
}
