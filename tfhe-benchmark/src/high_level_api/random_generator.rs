use rand::distributions::Standard;
use rand::prelude::*;
use tfhe::core_crypto::prelude::Numeric;
use tfhe::integer::server_key::ScalarMultiplier;

pub fn random_non_zero<T>() -> T
where
    Standard: Distribution<T>,
    T: Numeric,
{
    let mut rng = rand::rng();

    loop {
        let v: T = rng.gen();
        if v != T::ZERO {
            return v;
        }
    }
}

pub fn random_not_power_of_two<T>() -> T
where
    Standard: Distribution<T>,
    T: ScalarMultiplier,
{
    let mut rng = rand::rng();

    loop {
        let v: T = rng.gen();
        if !(v.is_power_of_two()) {
            return v;
        }
    }
}
