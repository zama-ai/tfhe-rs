/// A trait for objects which can be checked to be conformant with a parameter set
pub trait ParameterSetConformant {
    type ParameterSet;

    fn is_conformant(&self, parameter_set: &Self::ParameterSet) -> bool;
}
