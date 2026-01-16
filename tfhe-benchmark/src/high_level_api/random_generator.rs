use super::num_consts::NumConsts;
use rand::distributions::Standard;
use rand::prelude::*;
use std::ops::BitAnd;
use std::ops::Sub;

pub fn random_non_zero<T>() -> T
where
    Standard: Distribution<T>,
    T: Copy + PartialEq + NumConsts,
{
    let mut rng = rand::thread_rng();

    loop {
        let v: T = rng.gen();
        if v != T::zero() {
            return v;
        }
    }
}

pub fn random_not_power_of_two<T>() -> T
where
    Standard: Distribution<T>,
    T: Copy + PartialEq + BitAnd<Output = T> + Sub<Output = T> + NumConsts,
{
    let mut rng = rand::thread_rng();

    loop {
        let v: T = rng.gen();
        if !(v != T::zero() && (v & (v - T::one())) == T::zero()) {
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
