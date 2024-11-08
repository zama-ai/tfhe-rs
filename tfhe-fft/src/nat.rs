#![allow(dead_code)]
// TODO: remove this allow, clippy has a false positive on this for Plus2, Plus3 and Plus4

pub struct Successor<N>(pub N);
pub struct Zero;
pub type N0 = Zero;
pub type N1 = Successor<N0>;
pub type N2 = Successor<N1>;
pub type N3 = Successor<N2>;
pub type N4 = Successor<N3>;
pub type N5 = Successor<N4>;
pub type N6 = Successor<N5>;
pub type N7 = Successor<N6>;
pub type N8 = Successor<N7>;
pub type N9 = Successor<N8>;

pub trait Nat {
    const VALUE: usize;
}

impl Nat for Zero {
    const VALUE: usize = 0;
}
impl<N: Nat> Nat for Successor<N> {
    const VALUE: usize = N::VALUE + 1;
}

pub type Plus1<N> = Successor<N>;
pub type Plus2<N> = Successor<Plus1<N>>;
pub type Plus3<N> = Successor<Plus2<N>>;
pub type Plus4<N> = Successor<Plus3<N>>;
