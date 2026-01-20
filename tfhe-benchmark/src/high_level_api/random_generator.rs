use rand::distributions::Standard;
use rand::prelude::*;
use std::ops::{BitAnd, Sub};
use tfhe::core_crypto::prelude::Numeric;

pub fn random_non_zero<T>() -> T
where
    Standard: Distribution<T>,
    T: Numeric,
{
    let mut rng = rand::thread_rng();

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
    T: Numeric + Sub<Output = T> + BitAnd<Output = T>,
{
    let mut rng = rand::thread_rng();

    loop {
        let v: T = rng.gen();
        if !(v > T::ZERO && (v & (v - T::ONE)) == T::ZERO) {
            return v;
        }
    }
}

pub fn get_one<T>() -> T
where
    T: From<u8>,
{
    T::from(1)
}

pub fn random<T>() -> T
where
    Standard: Distribution<T>,
{
    rand::thread_rng().gen()
}
