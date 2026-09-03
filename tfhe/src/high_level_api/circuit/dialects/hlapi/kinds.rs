//! The different value types that exist in the HlApiDialect
//!
//! Sub-enums of [`ValueKind`] exist to statically encode op-family type constraints.
//!
//! - [`FheIntKind`]: integer types (`Uint`, `Int`). Used by arithmetic, ordering, shift-lhs,
//!   negation, scalar-arith, scalar-shift.
//! - [`FheKind`]: any non-compressed FHE type (`Uint`, `Int`, `Bool`). Used by bitwise, equality,
//!   scalar-bitwise, scalar-eq.
//! - [`ClearKind`]: any clear (non-encrypted) value type (`Uint`, `Int`, `Bool`). Used by
//!   `Constant` ops and as the "scalar-side" operand kind of every `*Scalar*` op family.
use super::type_system::ValueKind;

/// Kinds that support arithmetic, ordering, shifts/rotates, and negation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FheIntKind {
    Uint(u32),
    Int(u32),
}

impl FheIntKind {
    /// Returns the matching clear `ValueKind` (e.g. `FheIntKind::Uint(32)` →
    /// `ValueKind::Uint(32)`). Used by the builder when emitting a
    /// `Constant` to feed a `*Scalar*` op's clear-side operand.
    pub fn as_clear_value_kind(self) -> ValueKind {
        match self {
            Self::Uint(n) => ValueKind::Uint(n as usize),
            Self::Int(n) => ValueKind::Int(n as usize),
        }
    }

    /// Returns the matching `ClearKind`.
    pub fn as_clear_kind(self) -> ClearKind {
        match self {
            Self::Uint(n) => ClearKind::Uint(n),
            Self::Int(n) => ClearKind::Int(n),
        }
    }

    /// Returns the *unsigned* `ClearKind` of this kind's bit-width,
    /// regardless of signedness. Used for scalar operands that are
    /// semantically non-negative counts (shift and rotate amounts), so a
    /// signed lhs doesn't make negative amounts representable.
    pub fn as_unsigned_clear_kind(self) -> ClearKind {
        match self {
            Self::Uint(n) | Self::Int(n) => ClearKind::Uint(n),
        }
    }

    /// `ValueKind` counterpart of [`Self::as_unsigned_clear_kind`].
    pub fn as_unsigned_clear_value_kind(self) -> ValueKind {
        match self {
            Self::Uint(n) | Self::Int(n) => ValueKind::Uint(n as usize),
        }
    }
}

/// Kinds that support bitwise ops and equality. Excludes `CompressedList`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FheKind {
    Uint(u32),
    Int(u32),
    Bool,
}

impl FheKind {
    /// Returns the matching clear `ValueKind` (e.g. `FheKind::Bool`
    /// → `ValueKind::Bool`). Used by the builder for `EncryptTrivial` and
    /// other ops that consume a clear operand sized to a non-compressed kind.
    pub fn as_clear_value_kind(self) -> ValueKind {
        match self {
            Self::Uint(n) => ValueKind::Uint(n as usize),
            Self::Int(n) => ValueKind::Int(n as usize),
            Self::Bool => ValueKind::Bool,
        }
    }

    /// Returns the matching `ClearKind`.
    pub fn as_clear_kind(self) -> ClearKind {
        match self {
            Self::Uint(n) => ClearKind::Uint(n),
            Self::Int(n) => ClearKind::Int(n),
            Self::Bool => ClearKind::Bool,
        }
    }
}

/// Kinds that designate a clear (non-encrypted) value. Used by the `Constant`
/// op to produce clear values, and matches the shape of [`FheKind`]
/// on the clear side.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ClearKind {
    Uint(u32),
    Int(u32),
    Bool,
}

/// Returned by `TryFrom<ValueKind>` when the source kind is outside the
/// destination sub-enum's domain.
#[derive(Debug)]
pub struct KindConvertError {
    pub from: ValueKind,
}

impl From<FheIntKind> for ValueKind {
    fn from(k: FheIntKind) -> Self {
        match k {
            FheIntKind::Uint(n) => Self::FheUint(n as usize),
            FheIntKind::Int(n) => Self::FheInt(n as usize),
        }
    }
}

impl TryFrom<ValueKind> for FheIntKind {
    type Error = KindConvertError;

    fn try_from(k: ValueKind) -> Result<Self, Self::Error> {
        // Widths above u32::MAX are unrepresentable in the sub-enum;
        // reject rather than silently truncate.
        match k {
            ValueKind::FheUint(n) => u32::try_from(n)
                .map(Self::Uint)
                .map_err(|_| KindConvertError { from: k }),
            ValueKind::FheInt(n) => u32::try_from(n)
                .map(Self::Int)
                .map_err(|_| KindConvertError { from: k }),
            _ => Err(KindConvertError { from: k }),
        }
    }
}

impl From<FheKind> for ValueKind {
    fn from(k: FheKind) -> Self {
        match k {
            FheKind::Uint(n) => Self::FheUint(n as usize),
            FheKind::Int(n) => Self::FheInt(n as usize),
            FheKind::Bool => Self::FheBool,
        }
    }
}

impl TryFrom<ValueKind> for FheKind {
    type Error = KindConvertError;

    fn try_from(k: ValueKind) -> Result<Self, Self::Error> {
        match k {
            ValueKind::FheUint(n) => u32::try_from(n)
                .map(Self::Uint)
                .map_err(|_| KindConvertError { from: k }),
            ValueKind::FheInt(n) => u32::try_from(n)
                .map(Self::Int)
                .map_err(|_| KindConvertError { from: k }),
            ValueKind::FheBool => Ok(Self::Bool),
            _ => Err(KindConvertError { from: k }),
        }
    }
}

impl From<ClearKind> for ValueKind {
    fn from(k: ClearKind) -> Self {
        match k {
            ClearKind::Uint(n) => Self::Uint(n as usize),
            ClearKind::Int(n) => Self::Int(n as usize),
            ClearKind::Bool => Self::Bool,
        }
    }
}

impl TryFrom<ValueKind> for ClearKind {
    type Error = KindConvertError;

    fn try_from(k: ValueKind) -> Result<Self, Self::Error> {
        match k {
            ValueKind::Uint(n) => u32::try_from(n)
                .map(Self::Uint)
                .map_err(|_| KindConvertError { from: k }),
            ValueKind::Int(n) => u32::try_from(n)
                .map(Self::Int)
                .map_err(|_| KindConvertError { from: k }),
            ValueKind::Bool => Ok(Self::Bool),
            _ => Err(KindConvertError { from: k }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int_kind_round_trips() {
        for k in [FheIntKind::Uint(32), FheIntKind::Int(64)] {
            let v: ValueKind = k.into();
            let back: FheIntKind = v.try_into().unwrap();
            assert_eq!(k, back);
        }
    }

    #[test]
    fn non_compressed_kind_round_trips() {
        for k in [FheKind::Uint(32), FheKind::Int(64), FheKind::Bool] {
            let v: ValueKind = k.into();
            let back: FheKind = v.try_into().unwrap();
            assert_eq!(k, back);
        }
    }

    #[test]
    fn int_kind_rejects_bool_and_compressed() {
        assert!(FheIntKind::try_from(ValueKind::FheBool).is_err());
        assert!(FheIntKind::try_from(ValueKind::CompressedList).is_err());
    }

    #[test]
    fn non_compressed_kind_rejects_compressed() {
        assert!(FheKind::try_from(ValueKind::CompressedList).is_err());
    }

    #[test]
    fn clear_kind_round_trips() {
        for k in [ClearKind::Uint(32), ClearKind::Int(64), ClearKind::Bool] {
            let v: ValueKind = k.into();
            let back: ClearKind = v.try_into().unwrap();
            assert_eq!(k, back);
        }
    }

    #[test]
    fn clear_kind_rejects_fhe_and_compressed() {
        assert!(ClearKind::try_from(ValueKind::FheUint(32)).is_err());
        assert!(ClearKind::try_from(ValueKind::FheBool).is_err());
        assert!(ClearKind::try_from(ValueKind::CompressedList).is_err());
    }

    #[test]
    fn int_kind_as_clear_value_kind() {
        assert_eq!(
            FheIntKind::Uint(32).as_clear_value_kind(),
            ValueKind::Uint(32)
        );
        assert_eq!(
            FheIntKind::Int(64).as_clear_value_kind(),
            ValueKind::Int(64)
        );
    }

    #[test]
    fn non_compressed_kind_as_clear_value_kind() {
        assert_eq!(FheKind::Uint(32).as_clear_value_kind(), ValueKind::Uint(32));
        assert_eq!(FheKind::Int(64).as_clear_value_kind(), ValueKind::Int(64));
        assert_eq!(FheKind::Bool.as_clear_value_kind(), ValueKind::Bool);
    }
}
