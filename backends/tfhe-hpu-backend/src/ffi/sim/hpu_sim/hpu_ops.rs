//!
//! Define a trait for Hpu Operations
//! Enable to defer the associated implementation to tfhe-rs

pub trait HpuOps {
    fn load<T>(&mut self, rhs: &[T]);
    fn store<T>(&self, rhs: &mut [T]);
    fn add_assign(&mut self, rhs_a: Self, rhs_b: Self);
    fn sub_assign(&mut self, rhs_a: Self, rhs_b: Self);
    fn mac_assign(&mut self, rhs_a: Self, rhs_b: Self, scalar: usize);
    fn adds_assign(&mut self, rhs: Self, scalar: usize);
    fn subs_assign(&mut self, rhs: Self, scalar: usize);
    fn ssub_assign(&mut self, rhs: Self, scalar: usize);
    fn muls_assign(&mut self, rhs: Self, scalar: usize);
    fn pbs_assign(&mut self, rhs: Self);
}
