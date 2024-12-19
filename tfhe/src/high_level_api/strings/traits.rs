use crate::{FheBool, FheUint32};

pub trait FheEqIgnoreCase<Rhs = Self> {
    fn eq_ignore_case(&self, rhs: &Rhs) -> FheBool;
}

pub trait FheStringMatching<Rhs> {
    fn contains(&self, other: Rhs) -> FheBool;
    fn starts_with(&self, other: Rhs) -> FheBool;
    fn ends_with(&self, other: Rhs) -> FheBool;
}

pub trait FheStringFind<Rhs> {
    fn find(&self, other: Rhs) -> (FheUint32, FheBool);
    fn rfind(&self, other: Rhs) -> (FheUint32, FheBool);
}

pub trait FheStringStrip<Rhs>
where
    Self: Sized,
{
    fn strip_prefix(&self, pat: Rhs) -> (Self, FheBool);
    fn strip_suffix(&self, pat: Rhs) -> (Self, FheBool);
}

pub trait FheStringReplace<Rhs>
where
    Self: Sized,
{
    fn replace(&self, from: Rhs, to: &Self) -> Self;
}

pub trait FheStringReplaceN<Rhs, Count>
where
    Self: Sized,
{
    fn replacen(&self, from: Rhs, to: &Self, count: Count) -> Self;
}

pub trait FheStringRepeat<Count>
where
    Self: Sized,
{
    fn repeat(&self, count: Count) -> Self;
}
