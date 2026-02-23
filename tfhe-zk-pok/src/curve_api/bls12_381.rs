use super::*;

/// multiply EC point with scalar (= exponentiation in multiplicative notation)
fn mul_zp<T: Copy + Zero + Add<Output = T> + Group>(x: T, scalar: Zp) -> T {
    let zero = T::zero();
    let n: BigInt<4> = scalar.inner.into();

    if n == BigInt([0; 4]) {
        return zero;
    }

    let mut y = zero;
    let mut x = x;

    let n = n.0;
    for word in n {
        for idx in 0..64 {
            let bit = (word >> idx) & 1;
            if bit == 1 {
                y += x;
            }
            x.double_in_place();
        }
    }
    y
}

fn bigint_to_le_bytes(x: [u64; 6]) -> [u8; 6 * 8] {
    let mut buf = [0u8; 6 * 8];
    for (i, &xi) in x.iter().enumerate() {
        buf[i * 8..][..8].copy_from_slice(&xi.to_le_bytes());
    }
    buf
}

mod g1 {
    use tfhe_versionable::Versionize;

    use crate::serialization::{InvalidSerializedAffineError, SerializableG1Affine};

    use super::*;

    #[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash, Versionize)]
    #[serde(try_from = "SerializableG1Affine", into = "SerializableG1Affine")]
    #[versionize(try_from = "SerializableG1Affine", into = "SerializableG1Affine")]
    #[repr(transparent)]
    pub struct G1Affine {
        pub(crate) inner: ark_bls12_381::g1::G1Affine,
    }

    impl From<G1Affine> for SerializableAffine<SerializableFp> {
        fn from(value: G1Affine) -> Self {
            SerializableAffine::uncompressed(value.inner)
        }
    }

    impl TryFrom<SerializableAffine<SerializableFp>> for G1Affine {
        type Error = InvalidSerializedAffineError;

        fn try_from(value: SerializableAffine<SerializableFp>) -> Result<Self, Self::Error> {
            Ok(Self {
                inner: value.try_into()?,
            })
        }
    }

    impl Compressible for G1Affine {
        type Compressed = SerializableG1Affine;
        type UncompressError = InvalidSerializedAffineError;

        fn compress(&self) -> SerializableG1Affine {
            SerializableAffine::compressed(self.inner)
        }

        fn uncompress(compressed: Self::Compressed) -> Result<Self, Self::UncompressError> {
            compressed.try_into()
        }
    }

    impl G1Affine {
        pub fn multi_mul_scalar(bases: &[Self], scalars: &[Zp]) -> G1 {
            // SAFETY: interpreting a `repr(transparent)` pointer as its contents.
            G1 {
                inner: ark_bls12_381::g1::G1Projective::msm(
                    unsafe {
                        &*(bases as *const [G1Affine] as *const [ark_bls12_381::g1::G1Affine])
                    },
                    unsafe { &*(scalars as *const [Zp] as *const [ark_bls12_381::Fr]) },
                )
                .unwrap(),
            }
        }

        pub fn validate(&self) -> bool {
            self.inner.is_on_curve() && self.inner.is_in_correct_subgroup_assuming_on_curve()
        }
    }

    #[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Hash, Versionize)]
    #[serde(try_from = "SerializableG1Affine", into = "SerializableG1Affine")]
    #[versionize(try_from = "SerializableG1Affine", into = "SerializableG1Affine")]
    #[repr(transparent)]
    pub struct G1 {
        pub(crate) inner: ark_bls12_381::G1Projective,
    }

    impl From<G1> for SerializableAffine<SerializableFp> {
        fn from(value: G1) -> Self {
            SerializableAffine::uncompressed(value.inner.into_affine())
        }
    }

    impl TryFrom<SerializableG1Affine> for G1 {
        type Error = InvalidSerializedAffineError;

        fn try_from(value: SerializableAffine<SerializableFp>) -> Result<Self, Self::Error> {
            Ok(Self {
                inner: Affine::try_from(value)?.into(),
            })
        }
    }

    impl Compressible for G1 {
        type Compressed = SerializableG1Affine;
        type UncompressError = InvalidSerializedAffineError;

        fn compress(&self) -> SerializableG1Affine {
            SerializableAffine::compressed(self.inner.into_affine())
        }

        fn uncompress(compressed: Self::Compressed) -> Result<Self, Self::UncompressError> {
            compressed.try_into()
        }
    }

    impl fmt::Debug for G1 {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("G1")
                .field("x", &MontIntDisplay(&self.inner.x))
                .field("y", &MontIntDisplay(&self.inner.y))
                .field("z", &MontIntDisplay(&self.inner.z))
                .finish()
        }
    }

    impl G1 {
        pub const ZERO: Self = Self {
            inner: ark_bls12_381::G1Projective {
                x: MontFp!("1"),
                y: MontFp!("1"),
                z: MontFp!("0"),
            },
        };

        // https://github.com/zcash/librustzcash/blob/6e0364cd42a2b3d2b958a54771ef51a8db79dd29/pairing/src/bls12_381/README.md#g1
        pub const GENERATOR: Self = Self {
            inner: ark_bls12_381::G1Projective {
                x: MontFp!("3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507"),
                y: MontFp!("1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569"),
                z: MontFp!("1"),
            },
        };

        // Size in number of bytes when the [to_le_bytes]
        // function is called.
        // This is not the size after serialization!
        pub const BYTE_SIZE: usize = 2 * 6 * 8 + 1;

        pub fn mul_scalar(self, scalar: Zp) -> Self {
            Self {
                inner: mul_zp(self.inner, scalar),
            }
        }

        pub fn multi_mul_scalar(bases: &[Self], scalars: &[Zp]) -> Self {
            use rayon::prelude::*;
            let n_threads = rayon::current_num_threads();
            let chunk_size = bases.len().div_ceil(n_threads);
            bases
                .par_iter()
                .map(|&x| x.inner.into_affine())
                .chunks(chunk_size)
                .zip(scalars.par_iter().map(|&x| x.inner).chunks(chunk_size))
                .map(|(bases, scalars)| Self {
                    inner: ark_bls12_381::G1Projective::msm(&bases, &scalars).unwrap(),
                })
                .sum::<Self>()
        }

        pub fn to_le_bytes(self) -> [u8; Self::BYTE_SIZE] {
            let g = self.inner.into_affine();
            let x = bigint_to_le_bytes(g.x.0 .0);
            let y = bigint_to_le_bytes(g.y.0 .0);
            let mut buf = [0u8; 2 * 6 * 8 + 1];
            buf[..6 * 8].copy_from_slice(&x);
            buf[6 * 8..][..6 * 8].copy_from_slice(&y);
            buf[2 * 6 * 8] = g.infinity as u8;
            buf
        }

        pub fn double(self) -> Self {
            Self {
                inner: self.inner.double(),
            }
        }
    }

    impl Add for G1 {
        type Output = G1;

        #[inline]
        fn add(self, rhs: Self) -> Self::Output {
            G1 {
                inner: self.inner + rhs.inner,
            }
        }
    }

    impl Sub for G1 {
        type Output = G1;

        #[inline]
        fn sub(self, rhs: Self) -> Self::Output {
            G1 {
                inner: self.inner - rhs.inner,
            }
        }
    }

    impl AddAssign for G1 {
        #[inline]
        fn add_assign(&mut self, rhs: Self) {
            self.inner += rhs.inner
        }
    }

    impl SubAssign for G1 {
        #[inline]
        fn sub_assign(&mut self, rhs: Self) {
            self.inner -= rhs.inner
        }
    }

    impl core::iter::Sum for G1 {
        fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
            iter.fold(G1::ZERO, Add::add)
        }
    }

    impl Neg for G1 {
        type Output = Self;

        fn neg(self) -> Self::Output {
            Self { inner: -self.inner }
        }
    }
}

mod g2 {
    use tfhe_versionable::Versionize;

    use crate::serialization::{InvalidSerializedAffineError, SerializableG2Affine};

    use super::*;

    #[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash, Versionize)]
    #[serde(try_from = "SerializableG2Affine", into = "SerializableG2Affine")]
    #[versionize(try_from = "SerializableG2Affine", into = "SerializableG2Affine")]
    #[repr(transparent)]
    pub struct G2Affine {
        pub(crate) inner: ark_bls12_381::g2::G2Affine,
    }

    impl From<G2Affine> for SerializableAffine<SerializableFp2> {
        fn from(value: G2Affine) -> Self {
            SerializableAffine::uncompressed(value.inner)
        }
    }

    impl TryFrom<SerializableAffine<SerializableFp2>> for G2Affine {
        type Error = InvalidSerializedAffineError;

        fn try_from(value: SerializableAffine<SerializableFp2>) -> Result<Self, Self::Error> {
            Ok(Self {
                inner: value.try_into()?,
            })
        }
    }

    impl Compressible for G2Affine {
        type Compressed = SerializableG2Affine;

        type UncompressError = InvalidSerializedAffineError;

        fn compress(&self) -> SerializableAffine<SerializableFp2> {
            SerializableAffine::compressed(self.inner)
        }

        fn uncompress(compressed: Self::Compressed) -> Result<Self, Self::UncompressError> {
            compressed.try_into()
        }
    }

    impl G2Affine {
        pub fn multi_mul_scalar(bases: &[Self], scalars: &[Zp]) -> G2 {
            // SAFETY: interpreting a `repr(transparent)` pointer as its contents.
            G2 {
                inner: ark_bls12_381::g2::G2Projective::msm(
                    unsafe {
                        &*(bases as *const [G2Affine] as *const [ark_bls12_381::g2::G2Affine])
                    },
                    unsafe { &*(scalars as *const [Zp] as *const [ark_bls12_381::Fr]) },
                )
                .unwrap(),
            }
        }

        pub fn validate(&self) -> bool {
            self.inner.is_on_curve() && self.inner.is_in_correct_subgroup_assuming_on_curve()
        }
    }

    #[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Hash, Versionize)]
    #[serde(try_from = "SerializableG2Affine", into = "SerializableG2Affine")]
    #[versionize(try_from = "SerializableG2Affine", into = "SerializableG2Affine")]
    #[repr(transparent)]
    pub struct G2 {
        pub(crate) inner: ark_bls12_381::G2Projective,
    }

    impl From<G2> for SerializableG2Affine {
        fn from(value: G2) -> Self {
            SerializableAffine::uncompressed(value.inner.into_affine())
        }
    }

    impl TryFrom<SerializableG2Affine> for G2 {
        type Error = InvalidSerializedAffineError;

        fn try_from(value: SerializableAffine<SerializableFp2>) -> Result<Self, Self::Error> {
            Ok(Self {
                inner: Affine::try_from(value)?.into(),
            })
        }
    }

    impl Compressible for G2 {
        type Compressed = SerializableG2Affine;

        type UncompressError = InvalidSerializedAffineError;

        fn compress(&self) -> SerializableAffine<SerializableFp2> {
            SerializableAffine::compressed(self.inner.into_affine())
        }

        fn uncompress(compressed: Self::Compressed) -> Result<Self, Self::UncompressError> {
            compressed.try_into()
        }
    }

    impl fmt::Debug for G2 {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            #[allow(dead_code)]
            #[derive(Debug)]
            struct QuadExtField<T> {
                c0: T,
                c1: T,
            }

            f.debug_struct("G2")
                .field(
                    "x",
                    &QuadExtField {
                        c0: MontIntDisplay(&self.inner.x.c0),
                        c1: MontIntDisplay(&self.inner.x.c1),
                    },
                )
                .field(
                    "y",
                    &QuadExtField {
                        c0: MontIntDisplay(&self.inner.y.c0),
                        c1: MontIntDisplay(&self.inner.y.c1),
                    },
                )
                .field(
                    "z",
                    &QuadExtField {
                        c0: MontIntDisplay(&self.inner.z.c0),
                        c1: MontIntDisplay(&self.inner.z.c1),
                    },
                )
                .finish()
        }
    }

    impl G2 {
        pub const ZERO: Self = Self {
            inner: ark_bls12_381::G2Projective {
                x: ark_ff::QuadExtField {
                    c0: MontFp!("1"),
                    c1: MontFp!("0"),
                },
                y: ark_ff::QuadExtField {
                    c0: MontFp!("1"),
                    c1: MontFp!("0"),
                },
                z: ark_ff::QuadExtField {
                    c0: MontFp!("0"),
                    c1: MontFp!("0"),
                },
            },
        };

        // https://github.com/zcash/librustzcash/blob/6e0364cd42a2b3d2b958a54771ef51a8db79dd29/pairing/src/bls12_381/README.md#g2
        pub const GENERATOR: Self = Self {
            inner: ark_bls12_381::G2Projective {
                x: ark_ff::QuadExtField {
                    c0: MontFp!("352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160"),
                    c1: MontFp!("3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758"),
                },
                y: ark_ff::QuadExtField {
                    c0: MontFp!("1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905"),
                    c1: MontFp!("927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582"),
                },
                z: ark_ff::QuadExtField {
                    c0: MontFp!("1"),
                    c1: MontFp!("0") ,
                },
            },
        };

        // Size in number of bytes when the [to_le_bytes]
        // function is called.
        // This is not the size after serialization!
        pub const BYTE_SIZE: usize = 4 * 6 * 8 + 1;

        pub fn mul_scalar(self, scalar: Zp) -> Self {
            Self {
                inner: mul_zp(self.inner, scalar),
            }
        }

        pub fn multi_mul_scalar(bases: &[Self], scalars: &[Zp]) -> Self {
            use rayon::prelude::*;
            let n_threads = rayon::current_num_threads();
            let chunk_size = bases.len().div_ceil(n_threads);
            bases
                .par_iter()
                .map(|&x| x.inner.into_affine())
                .chunks(chunk_size)
                .zip(scalars.par_iter().map(|&x| x.inner).chunks(chunk_size))
                .map(|(bases, scalars)| Self {
                    inner: ark_bls12_381::G2Projective::msm(&bases, &scalars).unwrap(),
                })
                .sum::<Self>()
        }

        pub fn to_le_bytes(self) -> [u8; Self::BYTE_SIZE] {
            let g = self.inner.into_affine();
            let xc0 = bigint_to_le_bytes(g.x.c0.0 .0);
            let xc1 = bigint_to_le_bytes(g.x.c1.0 .0);
            let yc0 = bigint_to_le_bytes(g.y.c0.0 .0);
            let yc1 = bigint_to_le_bytes(g.y.c1.0 .0);
            let mut buf = [0u8; 4 * 6 * 8 + 1];
            buf[..6 * 8].copy_from_slice(&xc0);
            buf[6 * 8..][..6 * 8].copy_from_slice(&xc1);
            buf[2 * 6 * 8..][..6 * 8].copy_from_slice(&yc0);
            buf[3 * 6 * 8..][..6 * 8].copy_from_slice(&yc1);
            buf[4 * 6 * 8] = g.infinity as u8;
            buf
        }

        pub fn double(self) -> Self {
            Self {
                inner: self.inner.double(),
            }
        }
    }

    impl Add for G2 {
        type Output = G2;

        #[inline]
        fn add(self, rhs: Self) -> Self::Output {
            G2 {
                inner: self.inner + rhs.inner,
            }
        }
    }

    impl Sub for G2 {
        type Output = G2;

        #[inline]
        fn sub(self, rhs: Self) -> Self::Output {
            G2 {
                inner: self.inner - rhs.inner,
            }
        }
    }

    impl AddAssign for G2 {
        #[inline]
        fn add_assign(&mut self, rhs: Self) {
            self.inner += rhs.inner
        }
    }

    impl SubAssign for G2 {
        #[inline]
        fn sub_assign(&mut self, rhs: Self) {
            self.inner -= rhs.inner
        }
    }

    impl core::iter::Sum for G2 {
        fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
            iter.fold(G2::ZERO, Add::add)
        }
    }

    impl Neg for G2 {
        type Output = Self;

        fn neg(self) -> Self::Output {
            Self { inner: -self.inner }
        }
    }
}

mod gt {
    use crate::serialization::InvalidFpError;

    use super::*;
    use ark_ec::pairing::Pairing;
    use tfhe_versionable::Versionize;

    #[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Versionize, Hash)]
    #[serde(try_from = "SerializableFp12", into = "SerializableFp12")]
    #[versionize(try_from = "SerializableFp12", into = "SerializableFp12")]
    #[repr(transparent)]
    pub struct Gt {
        inner: ark_ec::pairing::PairingOutput<ark_bls12_381::Bls12_381>,
    }

    impl From<Gt> for SerializableFp12 {
        fn from(value: Gt) -> Self {
            value.inner.0.into()
        }
    }

    impl TryFrom<SerializableFp12> for Gt {
        type Error = InvalidFpError;

        fn try_from(value: SerializableFp12) -> Result<Self, Self::Error> {
            Ok(Self {
                inner: PairingOutput(value.try_into()?),
            })
        }
    }

    impl fmt::Debug for Gt {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            #[allow(dead_code)]
            #[derive(Debug)]
            struct QuadExtField<T> {
                c0: T,
                c1: T,
            }

            #[allow(dead_code)]
            #[derive(Debug)]
            struct CubicExtField<T> {
                c0: T,
                c1: T,
                c2: T,
            }

            #[allow(dead_code)]
            #[derive(Debug)]
            pub struct Gt<T> {
                inner: T,
            }

            f.debug_struct("Gt")
                .field(
                    "inner",
                    &Gt {
                        inner: QuadExtField {
                            c0: CubicExtField {
                                c0: QuadExtField {
                                    c0: MontIntDisplay(&self.inner.0.c0.c0.c0),
                                    c1: MontIntDisplay(&self.inner.0.c0.c0.c1),
                                },
                                c1: QuadExtField {
                                    c0: MontIntDisplay(&self.inner.0.c0.c1.c0),
                                    c1: MontIntDisplay(&self.inner.0.c0.c1.c1),
                                },
                                c2: QuadExtField {
                                    c0: MontIntDisplay(&self.inner.0.c0.c2.c0),
                                    c1: MontIntDisplay(&self.inner.0.c0.c2.c1),
                                },
                            },
                            c1: CubicExtField {
                                c0: QuadExtField {
                                    c0: MontIntDisplay(&self.inner.0.c1.c0.c0),
                                    c1: MontIntDisplay(&self.inner.0.c1.c0.c1),
                                },
                                c1: QuadExtField {
                                    c0: MontIntDisplay(&self.inner.0.c1.c1.c0),
                                    c1: MontIntDisplay(&self.inner.0.c1.c1.c1),
                                },
                                c2: QuadExtField {
                                    c0: MontIntDisplay(&self.inner.0.c1.c2.c0),
                                    c1: MontIntDisplay(&self.inner.0.c1.c2.c1),
                                },
                            },
                        },
                    },
                )
                .finish()
        }
    }

    impl Gt {
        pub fn pairing(g1: G1, g2: G2) -> Self {
            Self {
                inner: ark_bls12_381::Bls12_381::pairing(g1.inner, g2.inner),
            }
        }

        pub fn mul_scalar(self, scalar: Zp) -> Self {
            Self {
                inner: mul_zp(self.inner, scalar),
            }
        }
    }

    impl Add for Gt {
        type Output = Gt;

        #[inline]
        fn add(self, rhs: Self) -> Self::Output {
            Gt {
                inner: self.inner + rhs.inner,
            }
        }
    }

    impl Sub for Gt {
        type Output = Gt;

        #[inline]
        fn sub(self, rhs: Self) -> Self::Output {
            Gt {
                inner: self.inner - rhs.inner,
            }
        }
    }

    impl AddAssign for Gt {
        #[inline]
        fn add_assign(&mut self, rhs: Self) {
            self.inner += rhs.inner
        }
    }

    impl SubAssign for Gt {
        #[inline]
        fn sub_assign(&mut self, rhs: Self) {
            self.inner -= rhs.inner
        }
    }

    impl Neg for Gt {
        type Output = Self;

        fn neg(self) -> Self::Output {
            Self { inner: -self.inner }
        }
    }
}

mod zp {
    use crate::serialization::InvalidFpError;

    use super::*;
    use ark_ff::Fp;
    use tfhe_versionable::Versionize;
    use zeroize::Zeroize;

    fn redc(n: [u64; 4], nprime: u64, mut t: [u64; 6]) -> [u64; 4] {
        for i in 0..2 {
            let mut c = 0u64;
            let m = u64::wrapping_mul(t[i], nprime);

            for j in 0..4 {
                let x = t[i + j] as u128 + m as u128 * n[j] as u128 + c as u128;
                t[i + j] = x as u64;
                c = (x >> 64) as u64;
            }

            for j in 4..6 - i {
                let x = t[i + j] as u128 + c as u128;
                t[i + j] = x as u64;
                c = (x >> 64) as u64;
            }
        }

        let mut t = [t[2], t[3], t[4], t[5]];

        if t.into_iter().rev().ge(n.into_iter().rev()) {
            let mut o = false;
            for i in 0..4 {
                let (ti, o0) = u64::overflowing_sub(t[i], n[i]);
                let (ti, o1) = u64::overflowing_sub(ti, o as u64);
                o = o0 | o1;
                t[i] = ti;
            }
        }
        assert!(t.into_iter().rev().lt(n.into_iter().rev()));

        t
    }

    #[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Versionize, Hash, Zeroize)]
    #[serde(try_from = "SerializableFp", into = "SerializableFp")]
    #[versionize(try_from = "SerializableFp", into = "SerializableFp")]
    #[repr(transparent)]
    pub struct Zp {
        pub(crate) inner: ark_bls12_381::Fr,
    }

    impl From<Zp> for SerializableFp {
        fn from(value: Zp) -> Self {
            value.inner.into()
        }
    }
    impl TryFrom<SerializableFp> for Zp {
        type Error = InvalidFpError;

        fn try_from(value: SerializableFp) -> Result<Self, Self::Error> {
            Ok(Self {
                inner: value.try_into()?,
            })
        }
    }

    impl fmt::Debug for Zp {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_tuple("Zp")
                .field(&MontIntDisplay(&self.inner))
                .finish()
        }
    }

    impl Zp {
        pub const ZERO: Self = Self {
            inner: MontFp!("0"),
        };

        pub const ONE: Self = Self {
            inner: MontFp!("1"),
        };

        pub fn from_bigint(n: [u64; 4]) -> Self {
            Self {
                inner: BigInt(n).into(),
            }
        }

        pub fn from_u64(n: u64) -> Self {
            Self {
                inner: BigInt([n, 0, 0, 0]).into(),
            }
        }

        pub fn from_i64(n: i64) -> Self {
            let n_abs = Self::from_u64(n.unsigned_abs());
            if n > 0 {
                n_abs
            } else {
                -n_abs
            }
        }

        pub fn to_le_bytes(self) -> [u8; 4 * 8] {
            let buf = [
                self.inner.0 .0[0].to_le_bytes(),
                self.inner.0 .0[1].to_le_bytes(),
                self.inner.0 .0[2].to_le_bytes(),
                self.inner.0 .0[3].to_le_bytes(),
            ];
            unsafe { core::mem::transmute(buf) }
        }

        fn from_raw_u64x6(n: [u64; 6]) -> Self {
            const MODULUS: BigInt<4> = BigInt!(
                "52435875175126190479447740508185965837690552500527637822603658699938581184513"
            );

            const MODULUS_MONTGOMERY: u64 = 18446744069414584319;

            let mut n = n;
            // zero the two leading bits, so the result is <= MODULUS * 2^128
            n[5] &= (1 << 62) - 1;
            Zp {
                inner: Fp(
                    BigInt(redc(MODULUS.0, MODULUS_MONTGOMERY, n)),
                    core::marker::PhantomData,
                ),
            }
        }

        pub fn rand(rng: &mut impl rand::RngExt) -> Self {
            Self::from_raw_u64x6([
                rng.random::<u64>(),
                rng.random::<u64>(),
                rng.random::<u64>(),
                rng.random::<u64>(),
                rng.random::<u64>(),
                rng.random::<u64>(),
            ])
        }

        pub fn hash(values: &mut [Zp], data: &[&[u8]]) {
            use sha3::digest::{ExtendableOutput, Update, XofReader};

            let mut hasher = sha3::Shake256::default();
            for data in data {
                hasher.update(data);
            }
            let mut reader = hasher.finalize_xof();

            for value in values {
                let mut bytes = [0u8; 6 * 8];
                reader.read(&mut bytes);
                let bytes: [[u8; 8]; 6] = unsafe { core::mem::transmute(bytes) };
                *value = Zp::from_raw_u64x6(bytes.map(u64::from_le_bytes));
            }
        }

        pub fn hash_128bit(values: &mut [Zp], data: &[&[u8]]) {
            use sha3::digest::{ExtendableOutput, Update, XofReader};

            let mut hasher = sha3::Shake256::default();
            for data in data {
                hasher.update(data);
            }
            let mut reader = hasher.finalize_xof();

            for value in values {
                let mut bytes = [0u8; 2 * 8];
                reader.read(&mut bytes);
                let limbs: [u64; 2] = unsafe { core::mem::transmute(bytes) };
                *value = Zp {
                    inner: BigInt([limbs[0], limbs[1], 0, 0]).into(),
                };
            }
        }
    }

    impl Add for Zp {
        type Output = Zp;

        #[inline]
        fn add(self, rhs: Self) -> Self::Output {
            Zp {
                inner: self.inner + rhs.inner,
            }
        }
    }

    impl Sub for Zp {
        type Output = Zp;

        #[inline]
        fn sub(self, rhs: Self) -> Self::Output {
            Zp {
                inner: self.inner - rhs.inner,
            }
        }
    }

    impl Mul for Zp {
        type Output = Zp;

        #[inline]
        fn mul(self, rhs: Self) -> Self::Output {
            Zp {
                inner: self.inner * rhs.inner,
            }
        }
    }

    impl Div for Zp {
        type Output = Zp;

        #[inline]
        fn div(self, rhs: Self) -> Self::Output {
            Zp {
                inner: self.inner / rhs.inner,
            }
        }
    }
    impl AddAssign for Zp {
        #[inline]
        fn add_assign(&mut self, rhs: Self) {
            self.inner += rhs.inner
        }
    }

    impl SubAssign for Zp {
        #[inline]
        fn sub_assign(&mut self, rhs: Self) {
            self.inner -= rhs.inner
        }
    }

    impl Neg for Zp {
        type Output = Self;

        fn neg(self) -> Self::Output {
            Self { inner: -self.inner }
        }
    }

    impl core::iter::Sum for Zp {
        fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
            iter.fold(Zp::ZERO, Add::add)
        }
    }
}

pub use g1::{G1Affine, G1};
pub use g2::{G2Affine, G2};
pub use gt::Gt;
pub use zp::Zp;

#[cfg(test)]
mod tests {
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::collections::HashMap;

    use super::*;

    #[test]
    fn test_distributivity() {
        let a = Zp {
            inner: MontFp!(
                "20799633726231143268782044631117354647259165363910905818134484248029981143850"
            ),
        };
        let b = Zp {
            inner: MontFp!(
                "42333504039292951860879669847432876299949385605895551964353185488509497658948"
            ),
        };
        let c = Zp {
            inner: MontFp!(
                "6797004509292554067788526429737434481164547177696793280652530849910670196287"
            ),
        };

        assert_eq!((((a - b) * c) - (a * c - b * c)).inner, Zp::ZERO.inner);
    }

    #[test]
    fn test_serialization() {
        let rng = &mut StdRng::seed_from_u64(0);
        let alpha = Zp::rand(rng);
        let g_cur = G1::GENERATOR.mul_scalar(alpha);
        let g_hat_cur = G2::GENERATOR.mul_scalar(alpha);

        let alpha2: Zp = serde_json::from_str(&serde_json::to_string(&alpha).unwrap()).unwrap();
        assert_eq!(alpha, alpha2);

        let g_cur2: G1 = serde_json::from_str(&serde_json::to_string(&g_cur).unwrap()).unwrap();
        assert_eq!(g_cur, g_cur2);

        let g_hat_cur2: G2 =
            serde_json::from_str(&serde_json::to_string(&g_hat_cur).unwrap()).unwrap();
        assert_eq!(g_hat_cur, g_hat_cur2);
    }

    #[test]
    fn test_compressed_serialization() {
        let rng = &mut StdRng::seed_from_u64(0);
        let alpha = Zp::rand(rng);
        let g_cur = G1::GENERATOR.mul_scalar(alpha);
        let g_hat_cur = G2::GENERATOR.mul_scalar(alpha);

        let g_cur2 = G1::uncompress(
            serde_json::from_str(&serde_json::to_string(&g_cur.compress()).unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(g_cur, g_cur2);

        let g_hat_cur2 = G2::uncompress(
            serde_json::from_str(&serde_json::to_string(&g_hat_cur.compress()).unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(g_hat_cur, g_hat_cur2);
    }

    #[test]
    fn test_hasher_and_eq() {
        // we need to make sure if the points are the same
        // but the projective representations are different
        // then they still hash into the same thing
        let rng = &mut StdRng::seed_from_u64(0);
        let alpha = Zp::rand(rng);
        let a = G1::GENERATOR.mul_scalar(alpha);

        // serialization should convert the point to affine representation
        // after deserializing it we should have the same point
        // but with a different representation
        let a_affine: G1 = serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap();

        // the internal elements should be different
        assert_ne!(a.inner.x, a_affine.inner.x);
        assert_ne!(a.inner.y, a_affine.inner.y);
        assert_ne!(a.inner.z, a_affine.inner.z);

        // but equality and hasher should see the two as the same point
        assert_eq!(a, a_affine);
        let mut hm = HashMap::new();
        hm.insert(a, 1);
        assert_eq!(hm.len(), 1);
        hm.insert(a_affine, 2);
        assert_eq!(hm.len(), 1);
    }
}
