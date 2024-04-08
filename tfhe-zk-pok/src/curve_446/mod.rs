use ark_ec::bls12::{Bls12, Bls12Config, TwistType};
use ark_ff::fields::*;
use ark_ff::MontFp;

#[derive(MontConfig)]
#[modulus = "645383785691237230677916041525710377746967055506026847120930304831624105190538527824412673"]
#[generator = "7"]
#[small_subgroup_base = "3"]
#[small_subgroup_power = "1"]
pub struct FrConfig;
pub type Fr = Fp320<MontBackend<FrConfig, 5>>;

#[derive(MontConfig)]
#[modulus = "172824703542857155980071276579495962243492693522789898437834836356385656662277472896902502740297183690175962001546428467344062165330603"]
#[generator = "2"]
#[small_subgroup_base = "3"]
#[small_subgroup_power = "1"]
pub struct FqConfig;
pub type Fq = Fp448<MontBackend<FqConfig, 7>>;

pub type Fq2 = Fp2<Fq2Config>;

pub struct Fq2Config;

impl Fp2Config for Fq2Config {
    type Fp = Fq;

    /// NONRESIDUE = -1
    const NONRESIDUE: Fq = MontFp!("-1");

    /// Coefficients for the Frobenius automorphism.
    const FROBENIUS_COEFF_FP2_C1: &'static [Fq] = &[
        // Fq(-1)**(((q^0) - 1) / 2)
        Fq::ONE,
        // Fq(-1)**(((q^1) - 1) / 2)
        MontFp!("-1"),
    ];

    #[inline(always)]
    fn mul_fp_by_nonresidue_in_place(fp: &mut Self::Fp) -> &mut Self::Fp {
        fp.neg_in_place()
    }

    #[inline(always)]
    fn sub_and_mul_fp_by_nonresidue(y: &mut Self::Fp, x: &Self::Fp) {
        *y += x;
    }

    #[inline(always)]
    fn mul_fp_by_nonresidue_plus_one_and_add(y: &mut Self::Fp, x: &Self::Fp) {
        *y = *x;
    }

    fn mul_fp_by_nonresidue_and_add(y: &mut Self::Fp, x: &Self::Fp) {
        y.neg_in_place();
        *y += x;
    }
}

pub type Fq6 = Fp6<Fq6Config>;

#[derive(Clone, Copy)]
pub struct Fq6Config;

impl Fp6Config for Fq6Config {
    type Fp2Config = Fq2Config;

    /// NONRESIDUE = (U + 1)
    const NONRESIDUE: Fq2 = Fq2::new(Fq::ONE, Fq::ONE);

    const FROBENIUS_COEFF_FP6_C1: &'static [Fq2] = &[
        // Fp2::NONRESIDUE^(((q^0) - 1) / 3)
        Fq2::new(
            Fq::ONE,
            Fq::ZERO,
        ),
        // Fp2::NONRESIDUE^(((q^1) - 1) / 3)
        Fq2::new(
            Fq::ZERO,
            MontFp!("-18292478899820133222385880210918854254706405831091403105831645830694649873798259945392135397923436410689931051013"),
        ),
        // Fp2::NONRESIDUE^(((q^2) - 1) / 3)
        Fq2::new(
            MontFp!("18292478899820133222385880210918854254706405831091403105831645830694649873798259945392135397923436410689931051012"),
            Fq::ZERO,
        ),
        // Fp2::NONRESIDUE^(((q^3) - 1) / 3)
        Fq2::new(
            Fq::ZERO,
            Fq::ONE,
        ),
        // Fp2::NONRESIDUE^(((q^4) - 1) / 3)
        Fq2::new(
            MontFp!("-18292478899820133222385880210918854254706405831091403105831645830694649873798259945392135397923436410689931051013"),
            Fq::ZERO,
        ),
        // Fp2::NONRESIDUE^(((q^5) - 1) / 3)
        Fq2::new(
            Fq::ZERO,
            MontFp!("18292478899820133222385880210918854254706405831091403105831645830694649873798259945392135397923436410689931051012"),
        ),
        ];

    const FROBENIUS_COEFF_FP6_C2: &'static [Fq2] = &[
        // Fq2(u + 1)**(((2q^0) - 2) / 3)
        Fq2::new(
            Fq::ONE,
            Fq::ZERO,
        ),
        // Fq2(u + 1)**(((2q^1) - 2) / 3)
        Fq2::new(
            MontFp!("-18292478899820133222385880210918854254706405831091403105831645830694649873798259945392135397923436410689931051012"),
            Fq::ZERO,
        ),
        // Fq2(u + 1)**(((2q^2) - 2) / 3)
        Fq2::new(
            MontFp!("-18292478899820133222385880210918854254706405831091403105831645830694649873798259945392135397923436410689931051013"),
            Fq::ZERO,
        ),
        // Fq2(u + 1)**(((2q^3) - 2) / 3)
        Fq2::new(
            MontFp!("-1"),
            Fq::ZERO,
        ),
        // Fq2(u + 1)**(((2q^4) - 2) / 3)
        Fq2::new(
            MontFp!("18292478899820133222385880210918854254706405831091403105831645830694649873798259945392135397923436410689931051012"),
            Fq::ZERO,
        ),
        // Fq2(u + 1)**(((2q^5) - 2) / 3)
        Fq2::new(
            MontFp!("18292478899820133222385880210918854254706405831091403105831645830694649873798259945392135397923436410689931051013"),
            Fq::ZERO,
        ),
    ];

    /// Multiply this element by the quadratic nonresidue 1 + u.
    /// Make this generic.
    fn mul_fp2_by_nonresidue_in_place(fe: &mut Fq2) -> &mut Fq2 {
        let t0 = fe.c0;
        fe.c0 -= &fe.c1;
        fe.c1 += &t0;
        fe
    }
}

pub type Fq12 = Fp12<Fq12Config>;

#[derive(Clone, Copy)]
pub struct Fq12Config;

impl Fp12Config for Fq12Config {
    type Fp6Config = Fq6Config;

    const NONRESIDUE: Fq6 = Fq6::new(Fq2::ZERO, Fq2::ONE, Fq2::ZERO);

    const FROBENIUS_COEFF_FP12_C1: &'static [Fq2] = &[
        // Fp2::NONRESIDUE^(((q^0) - 1) / 6)
        Fq2::new(
            Fq::ONE,
            Fq::ZERO,
        ),
        // Fp2::NONRESIDUE^(((q^1) - 1) / 6)
        Fq2::new(
            MontFp!("22118644822122453894295732432166425368368980329889476319266915965514828099635526724748286229964921634997234117686841299669336163301597"),
            MontFp!("-22118644822122453894295732432166425368368980329889476319266915965514828099635526724748286229964921634997234117686841299669336163301597"),
        ),
        // Fp2::NONRESIDUE^(((q^2) - 1) / 6)
        Fq2::new(
            MontFp!("18292478899820133222385880210918854254706405831091403105831645830694649873798259945392135397923436410689931051013"),
            Fq::ZERO,
        ),
        // Fp2::NONRESIDUE^(((q^3) - 1) / 6)
        Fq2::new(
            MontFp!("-84459159508829117195668840503504856816171858703899096210464197465513610215112549935889502423482516188066933947513637464187184810836060"),
            MontFp!("84459159508829117195668840503504856816171858703899096210464197465513610215112549935889502423482516188066933947513637464187184810836060"),
        ),
        // Fp2::NONRESIDUE^(((q^4) - 1) / 6)
        Fq2::new(
            MontFp!("18292478899820133222385880210918854254706405831091403105831645830694649873798259945392135397923436410689931051012"),
            Fq::ZERO,
        ),
        // Fp2::NONRESIDUE^(((q^5) - 1) / 6)
        Fq2::new(
            MontFp!("66246899211905584890106703643824680058951854489001325908103722925357218347529396236264714086849745867111793936345949703487541191192946"),
            MontFp!("-66246899211905584890106703643824680058951854489001325908103722925357218347529396236264714086849745867111793936345949703487541191192946"),
        ),
        // Fp2::NONRESIDUE^(((q^6) - 1) / 6)
        Fq2::new(
            MontFp!("-1"),
            Fq::ZERO,
        ),
        // Fp2::NONRESIDUE^(((q^7) - 1) / 6)
        Fq2::new(
            MontFp!("-22118644822122453894295732432166425368368980329889476319266915965514828099635526724748286229964921634997234117686841299669336163301597"),
            MontFp!("22118644822122453894295732432166425368368980329889476319266915965514828099635526724748286229964921634997234117686841299669336163301597"),
        ),
        // Fp2::NONRESIDUE^(((q^8) - 1) / 6)
        Fq2::new(
            MontFp!("-18292478899820133222385880210918854254706405831091403105831645830694649873798259945392135397923436410689931051013"),
            Fq::ZERO,
        ),
        // Fp2::NONRESIDUE^(((q^9) - 1) / 6)
        Fq2::new(
            MontFp!("84459159508829117195668840503504856816171858703899096210464197465513610215112549935889502423482516188066933947513637464187184810836060"),
            MontFp!("-84459159508829117195668840503504856816171858703899096210464197465513610215112549935889502423482516188066933947513637464187184810836060"),
        ),
        // Fp2::NONRESIDUE^(((q^10) - 1) / 6)
        Fq2::new(
            MontFp!("-18292478899820133222385880210918854254706405831091403105831645830694649873798259945392135397923436410689931051012"),
            Fq::ZERO,
        ),
        // Fp2::NONRESIDUE^(((q^11) - 1) / 6)
        Fq2::new(
            MontFp!("-66246899211905584890106703643824680058951854489001325908103722925357218347529396236264714086849745867111793936345949703487541191192946"),
            MontFp!("66246899211905584890106703643824680058951854489001325908103722925357218347529396236264714086849745867111793936345949703487541191192946"),
        ),
    ];
}

pub type Bls12_446 = Bls12<Config>;
use g1::G1Affine;
use g2::G2Affine;

pub struct Config;

impl Bls12Config for Config {
    const X: &'static [u64] = &[0x8204000000020001, 0x600];
    const X_IS_NEGATIVE: bool = true;
    const TWIST_TYPE: TwistType = TwistType::M;
    type Fp = Fq;
    type Fp2Config = Fq2Config;
    type Fp6Config = Fq6Config;
    type Fp12Config = Fq12Config;
    type G1Config = g1::Config;
    type G2Config = g2::Config;
}

pub mod util {
    use ark_ec::short_weierstrass::Affine;
    use ark_ec::AffineRepr;
    use ark_ff::{BigInteger448, PrimeField};
    use ark_serialize::SerializationError;

    use super::g1::Config as G1Config;
    use super::g2::Config as G2Config;
    use super::{Fq, Fq2, G1Affine, G2Affine};

    pub const G1_SERIALIZED_SIZE: usize = 57;
    pub const G2_SERIALIZED_SIZE: usize = 114;

    pub struct EncodingFlags {
        pub is_compressed: bool,
        pub is_infinity: bool,
        pub is_lexographically_largest: bool,
    }

    impl EncodingFlags {
        pub fn get_flags(bytes: &[u8]) -> Self {
            let compression_flag_set = (bytes[0] >> 7) & 1;
            let infinity_flag_set = (bytes[0] >> 6) & 1;
            let sort_flag_set = (bytes[0] >> 5) & 1;

            Self {
                is_compressed: compression_flag_set == 1,
                is_infinity: infinity_flag_set == 1,
                is_lexographically_largest: sort_flag_set == 1,
            }
        }
        pub fn encode_flags(&self, bytes: &mut [u8]) {
            if self.is_compressed {
                bytes[0] |= 1 << 7;
            }

            if self.is_infinity {
                bytes[0] |= 1 << 6;
            }

            if self.is_compressed && !self.is_infinity && self.is_lexographically_largest {
                bytes[0] |= 1 << 5;
            }
        }
    }

    pub(crate) fn deserialize_fq(bytes: [u8; 56]) -> Option<Fq> {
        let mut tmp = BigInteger448::new([0, 0, 0, 0, 0, 0, 0]);

        // Note: The following unwraps are if the compiler cannot convert
        // the byte slice into [u8;8], we know this is infallible since we
        // are providing the indices at compile time and bytes has a fixed size
        tmp.0[6] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[0..8]).unwrap());
        tmp.0[5] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[8..16]).unwrap());
        tmp.0[4] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[16..24]).unwrap());
        tmp.0[3] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[24..32]).unwrap());
        tmp.0[2] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[32..40]).unwrap());
        tmp.0[1] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[40..48]).unwrap());
        tmp.0[0] = u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[48..56]).unwrap());

        Fq::from_bigint(tmp)
    }

    pub(crate) fn serialize_fq(field: Fq) -> [u8; 56] {
        let mut result = [0u8; 56];

        let rep = field.into_bigint();

        result[0..8].copy_from_slice(&rep.0[6].to_be_bytes());
        result[8..16].copy_from_slice(&rep.0[5].to_be_bytes());
        result[16..24].copy_from_slice(&rep.0[4].to_be_bytes());
        result[24..32].copy_from_slice(&rep.0[3].to_be_bytes());
        result[32..40].copy_from_slice(&rep.0[2].to_be_bytes());
        result[40..48].copy_from_slice(&rep.0[1].to_be_bytes());
        result[48..56].copy_from_slice(&rep.0[0].to_be_bytes());

        result
    }

    pub(crate) fn read_fq_with_offset(
        bytes: &[u8],
        offset: usize,
    ) -> Result<Fq, ark_serialize::SerializationError> {
        let mut tmp = [0; G1_SERIALIZED_SIZE - 1];
        // read `G1_SERIALIZED_SIZE` bytes
        tmp.copy_from_slice(
            &bytes[offset * G1_SERIALIZED_SIZE + 1..G1_SERIALIZED_SIZE * (offset + 1)],
        );

        deserialize_fq(tmp).ok_or(SerializationError::InvalidData)
    }

    pub(crate) fn read_g1_compressed<R: ark_serialize::Read>(
        mut reader: R,
    ) -> Result<Affine<G1Config>, ark_serialize::SerializationError> {
        let mut bytes = [0u8; G1_SERIALIZED_SIZE];
        reader
            .read_exact(&mut bytes)
            .ok()
            .ok_or(SerializationError::InvalidData)?;

        // Obtain the three flags from the start of the byte sequence
        let flags = EncodingFlags::get_flags(&bytes[..]);

        // we expect to be deserializing a compressed point
        if !flags.is_compressed {
            return Err(SerializationError::UnexpectedFlags);
        }

        if flags.is_infinity {
            return Ok(G1Affine::zero());
        }

        // Attempt to obtain the x-coordinate
        let x = read_fq_with_offset(&bytes, 0)?;

        let p = G1Affine::get_point_from_x_unchecked(x, flags.is_lexographically_largest)
            .ok_or(SerializationError::InvalidData)?;

        Ok(p)
    }

    pub(crate) fn read_g1_uncompressed<R: ark_serialize::Read>(
        mut reader: R,
    ) -> Result<Affine<G1Config>, ark_serialize::SerializationError> {
        let mut bytes = [0u8; 2 * G1_SERIALIZED_SIZE];
        reader
            .read_exact(&mut bytes)
            .map_err(|_| SerializationError::InvalidData)?;

        // Obtain the three flags from the start of the byte sequence
        let flags = EncodingFlags::get_flags(&bytes[..]);

        // we expect to be deserializing an uncompressed point
        if flags.is_compressed {
            return Err(SerializationError::UnexpectedFlags);
        }

        if flags.is_infinity {
            return Ok(G1Affine::zero());
        }

        // Attempt to obtain the x-coordinate
        let x = read_fq_with_offset(&bytes, 0)?;
        // Attempt to obtain the y-coordinate
        let y = read_fq_with_offset(&bytes, 1)?;

        let p = G1Affine::new_unchecked(x, y);

        Ok(p)
    }

    pub(crate) fn read_g2_compressed<R: ark_serialize::Read>(
        mut reader: R,
    ) -> Result<Affine<G2Config>, ark_serialize::SerializationError> {
        let mut bytes = [0u8; G2_SERIALIZED_SIZE];
        reader
            .read_exact(&mut bytes)
            .map_err(|_| SerializationError::InvalidData)?;

        // Obtain the three flags from the start of the byte sequence
        let flags = EncodingFlags::get_flags(&bytes);

        // we expect to be deserializing a compressed point
        if !flags.is_compressed {
            return Err(SerializationError::UnexpectedFlags);
        }

        if flags.is_infinity {
            return Ok(G2Affine::zero());
        }

        // Attempt to obtain the x-coordinate
        let xc1 = read_fq_with_offset(&bytes, 0)?;
        let xc0 = read_fq_with_offset(&bytes, 1)?;

        let x = Fq2::new(xc0, xc1);

        let p = G2Affine::get_point_from_x_unchecked(x, flags.is_lexographically_largest)
            .ok_or(SerializationError::InvalidData)?;

        Ok(p)
    }

    pub(crate) fn read_g2_uncompressed<R: ark_serialize::Read>(
        mut reader: R,
    ) -> Result<Affine<G2Config>, ark_serialize::SerializationError> {
        let mut bytes = [0u8; 2 * G2_SERIALIZED_SIZE];
        reader
            .read_exact(&mut bytes)
            .map_err(|_| SerializationError::InvalidData)?;

        // Obtain the three flags from the start of the byte sequence
        let flags = EncodingFlags::get_flags(&bytes);

        // we expect to be deserializing an uncompressed point
        if flags.is_compressed {
            return Err(SerializationError::UnexpectedFlags);
        }

        if flags.is_infinity {
            return Ok(G2Affine::zero());
        }

        // Attempt to obtain the x-coordinate
        let xc1 = read_fq_with_offset(&bytes, 0)?;
        let xc0 = read_fq_with_offset(&bytes, 1)?;
        let x = Fq2::new(xc0, xc1);

        // Attempt to obtain the y-coordinate
        let yc1 = read_fq_with_offset(&bytes, 2)?;
        let yc0 = read_fq_with_offset(&bytes, 3)?;
        let y = Fq2::new(yc0, yc1);

        let p = G2Affine::new_unchecked(x, y);

        Ok(p)
    }
}

pub mod g1 {
    use super::util::{
        read_g1_compressed, read_g1_uncompressed, serialize_fq, EncodingFlags, G1_SERIALIZED_SIZE,
    };
    use super::{Fq, Fr};
    use ark_ec::bls12::Bls12Config;
    use ark_ec::models::CurveConfig;
    use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
    use ark_ec::{bls12, AffineRepr, Group};
    use ark_ff::{Field, MontFp, One, PrimeField, Zero};
    use ark_serialize::{Compress, SerializationError};
    use core::ops::Neg;

    #[derive(Clone, Default, PartialEq, Eq)]
    pub struct Config;

    impl CurveConfig for Config {
        type BaseField = Fq;
        type ScalarField = Fr;

        /// COFACTOR = (x - 1)^2 / 3  = 267785939737784928360481681640896166738700972
        const COFACTOR: &'static [u64] = &[0xad5aaaac0002aaac, 0x2602b0055d560ab0, 0xc0208];

        /// COFACTOR_INV = COFACTOR^{-1} mod r
        /// = 645383785691237230677779421366207365261112665008071669867241543525136277620937226389553150
        const COFACTOR_INV: Fr =
        MontFp!("645383785691237230677779421366207365261112665008071669867241543525136277620937226389553150");
    }

    pub type G1Affine = bls12::G1Affine<super::Config>;
    pub type G1Projective = bls12::G1Projective<super::Config>;

    impl SWCurveConfig for Config {
        /// COEFF_A = 0
        const COEFF_A: Fq = Fq::ZERO;

        /// COEFF_B = 1
        const COEFF_B: Fq = MontFp!("1");

        /// AFFINE_GENERATOR_COEFFS = (G1_GENERATOR_X, G1_GENERATOR_Y)
        const GENERATOR: G1Affine = G1Affine::new_unchecked(G1_GENERATOR_X, G1_GENERATOR_Y);

        #[inline(always)]
        fn mul_by_a(_: Self::BaseField) -> Self::BaseField {
            Self::BaseField::zero()
        }

        #[inline]
        fn is_in_correct_subgroup_assuming_on_curve(p: &G1Affine) -> bool {
            // Algorithm from Section 6 of https://eprint.iacr.org/2021/1130.
            //
            // Check that endomorphism_p(P) == -[X^2]P

            // An early-out optimization described in Section 6.
            // If uP == P but P != point of infinity, then the point is not in the right
            // subgroup.
            let x_times_p = p.mul_bigint(super::Config::X);
            if x_times_p.eq(p) && !p.infinity {
                return false;
            }

            let minus_x_squared_times_p = x_times_p.mul_bigint(super::Config::X).neg();
            let endomorphism_p = endomorphism(p);
            minus_x_squared_times_p.eq(&endomorphism_p)
        }

        #[inline]
        fn clear_cofactor(p: &G1Affine) -> G1Affine {
            // Using the effective cofactor, as explained in
            // Section 5 of https://eprint.iacr.org/2019/403.pdf.
            //
            // It is enough to multiply by (1 - x), instead of (x - 1)^2 / 3
            let h_eff = one_minus_x().into_bigint();
            Config::mul_affine(p, h_eff.as_ref()).into()
        }

        fn deserialize_with_mode<R: ark_serialize::Read>(
            mut reader: R,
            compress: ark_serialize::Compress,
            validate: ark_serialize::Validate,
        ) -> Result<Affine<Self>, ark_serialize::SerializationError> {
            let p = if compress == ark_serialize::Compress::Yes {
                read_g1_compressed(&mut reader)?
            } else {
                read_g1_uncompressed(&mut reader)?
            };

            if validate == ark_serialize::Validate::Yes
                && !p.is_in_correct_subgroup_assuming_on_curve()
            {
                return Err(SerializationError::InvalidData);
            }
            Ok(p)
        }

        fn serialize_with_mode<W: ark_serialize::Write>(
            item: &Affine<Self>,
            mut writer: W,
            compress: ark_serialize::Compress,
        ) -> Result<(), SerializationError> {
            let encoding = EncodingFlags {
                is_compressed: compress == ark_serialize::Compress::Yes,
                is_infinity: item.is_zero(),
                is_lexographically_largest: item.y > -item.y,
            };
            let mut p = *item;
            if encoding.is_infinity {
                p = G1Affine::zero();
            }
            // need to access the field struct `x` directly, otherwise we get None from xy()
            // method
            let x_bytes = serialize_fq(p.x);
            if encoding.is_compressed {
                let mut bytes = [0u8; G1_SERIALIZED_SIZE];
                bytes[1..].copy_from_slice(&x_bytes);

                encoding.encode_flags(&mut bytes);
                writer.write_all(&bytes)?;
            } else {
                let mut bytes = [0u8; 2 * G1_SERIALIZED_SIZE];
                bytes[1..1 + G1_SERIALIZED_SIZE].copy_from_slice(&x_bytes[..]);
                bytes[2 + G1_SERIALIZED_SIZE..].copy_from_slice(&serialize_fq(p.y)[..]);

                encoding.encode_flags(&mut bytes);
                writer.write_all(&bytes)?;
            };

            Ok(())
        }

        fn serialized_size(compress: Compress) -> usize {
            if compress == Compress::Yes {
                G1_SERIALIZED_SIZE
            } else {
                G1_SERIALIZED_SIZE * 2
            }
        }
    }

    fn one_minus_x() -> Fr {
        const X: Fr = Fr::from_sign_and_limbs(!super::Config::X_IS_NEGATIVE, super::Config::X);
        Fr::one() - X
    }

    /// G1_GENERATOR_X =
    /// 143189966182216199425404656824735381247272236095050141599848381692039676741476615087722874458136990266833440576646963466074693171606778
    pub const G1_GENERATOR_X: Fq = MontFp!("143189966182216199425404656824735381247272236095050141599848381692039676741476615087722874458136990266833440576646963466074693171606778");

    /// G1_GENERATOR_Y =
    /// 75202396197342917254523279069469674666303680671605970245803554133573745859131002231546341942288521574682619325841484506619191207488304
    pub const G1_GENERATOR_Y: Fq = MontFp!("75202396197342917254523279069469674666303680671605970245803554133573745859131002231546341942288521574682619325841484506619191207488304");

    /// BETA is a non-trivial cubic root of unity in Fq.
    pub const BETA: Fq = MontFp!("18292478899820133222385880210918854254706405831091403105831645830694649873798259945392135397923436410689931051012");

    pub fn endomorphism(p: &Affine<Config>) -> Affine<Config> {
        // Endomorphism of the points on the curve.
        // endomorphism_p(x,y) = (BETA * x, y)
        // where BETA is a non-trivial cubic root of unity in Fq.
        let mut res = *p;
        res.x *= BETA;
        res
    }
}

pub mod g2 {
    use super::util::{
        read_g2_compressed, read_g2_uncompressed, serialize_fq, EncodingFlags, G2_SERIALIZED_SIZE,
    };
    use super::*;
    use ark_ec::models::CurveConfig;
    use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
    use ark_ec::{bls12, AffineRepr};
    use ark_ff::{MontFp, Zero};
    use ark_serialize::{Compress, SerializationError};

    pub type G2Affine = bls12::G2Affine<super::Config>;
    pub type G2Projective = bls12::G2Projective<super::Config>;

    #[derive(Clone, Default, PartialEq, Eq)]
    pub struct Config;

    impl CurveConfig for Config {
        type BaseField = Fq2;
        type ScalarField = Fr;

        /// COFACTOR = (x^8 - 4 x^7 + 5 x^6) - (4 x^4 + 6 x^3 - 4 x^2 - 4 x + 13) //
        /// 9
        /// = 46280025648128091779281203587029183771098593081950199160533444883894201638329761721685747232785203763275581499269893683911356926248942802726857101798724933488377584092259436345573
        const COFACTOR: &'static [u64] = &[
            0xce555594000638e5,
            0xa75088593e6a92ef,
            0xc81e026dd55b51d6,
            0x47f8e24b79369c54,
            0x74c3560ced298d51,
            0x7cefe5c3dd2555cb,
            0x657742bf55690156,
            0x5780484639bf731d,
            0x3988a06f1bb3444d,
            0x2daee,
        ];

        /// COFACTOR_INV = COFACTOR^{-1} mod r
        /// 420747440395392227734782296805460539842466911252881029283882861015362447833828968293150382
        const COFACTOR_INV: Fr = MontFp!(
            "420747440395392227734782296805460539842466911252881029283882861015362447833828968293150382"
        );
    }

    impl SWCurveConfig for Config {
        /// COEFF_A = [0, 0]
        const COEFF_A: Fq2 = Fq2::new(g1::Config::COEFF_A, g1::Config::COEFF_A);

        /// COEFF_B = [1, 1]
        const COEFF_B: Fq2 = Fq2::new(g1::Config::COEFF_B, g1::Config::COEFF_B);

        /// AFFINE_GENERATOR_COEFFS = (G2_GENERATOR_X, G2_GENERATOR_Y)
        const GENERATOR: G2Affine = G2Affine::new_unchecked(G2_GENERATOR_X, G2_GENERATOR_Y);

        #[inline(always)]
        fn mul_by_a(_: Self::BaseField) -> Self::BaseField {
            Self::BaseField::zero()
        }

        fn deserialize_with_mode<R: ark_serialize::Read>(
            mut reader: R,
            compress: ark_serialize::Compress,
            validate: ark_serialize::Validate,
        ) -> Result<Affine<Self>, ark_serialize::SerializationError> {
            let p = if compress == ark_serialize::Compress::Yes {
                read_g2_compressed(&mut reader)?
            } else {
                read_g2_uncompressed(&mut reader)?
            };

            if validate == ark_serialize::Validate::Yes
                && !p.is_in_correct_subgroup_assuming_on_curve()
            {
                return Err(SerializationError::InvalidData);
            }
            Ok(p)
        }

        fn serialize_with_mode<W: ark_serialize::Write>(
            item: &Affine<Self>,
            mut writer: W,
            compress: ark_serialize::Compress,
        ) -> Result<(), SerializationError> {
            let encoding = EncodingFlags {
                is_compressed: compress == ark_serialize::Compress::Yes,
                is_infinity: item.is_zero(),
                is_lexographically_largest: item.y > -item.y,
            };
            let mut p = *item;
            if encoding.is_infinity {
                p = G2Affine::zero();
            }

            let mut x_bytes = [0u8; G2_SERIALIZED_SIZE];
            let c1_bytes = serialize_fq(p.x.c1);
            let c0_bytes = serialize_fq(p.x.c0);
            x_bytes[1..56 + 1].copy_from_slice(&c1_bytes[..]);
            x_bytes[56 + 2..114].copy_from_slice(&c0_bytes[..]);
            if encoding.is_compressed {
                let mut bytes: [u8; G2_SERIALIZED_SIZE] = x_bytes;

                encoding.encode_flags(&mut bytes);
                writer.write_all(&bytes)?;
            } else {
                let mut bytes = [0u8; 2 * G2_SERIALIZED_SIZE];

                let mut y_bytes = [0u8; G2_SERIALIZED_SIZE];
                let c1_bytes = serialize_fq(p.y.c1);
                let c0_bytes = serialize_fq(p.y.c0);
                y_bytes[1..56 + 1].copy_from_slice(&c1_bytes[..]);
                y_bytes[56 + 2..114].copy_from_slice(&c0_bytes[..]);
                bytes[0..G2_SERIALIZED_SIZE].copy_from_slice(&x_bytes);
                bytes[G2_SERIALIZED_SIZE..].copy_from_slice(&y_bytes);

                encoding.encode_flags(&mut bytes);
                writer.write_all(&bytes)?;
            };

            Ok(())
        }

        fn serialized_size(compress: ark_serialize::Compress) -> usize {
            if compress == Compress::Yes {
                G2_SERIALIZED_SIZE
            } else {
                2 * G2_SERIALIZED_SIZE
            }
        }
    }

    pub const G2_GENERATOR_X: Fq2 = Fq2::new(G2_GENERATOR_X_C0, G2_GENERATOR_X_C1);
    pub const G2_GENERATOR_Y: Fq2 = Fq2::new(G2_GENERATOR_Y_C0, G2_GENERATOR_Y_C1);

    /// G2_GENERATOR_X_C0 =
    /// 96453755443802578867745476081903764610578492683850270111202389209355548711427786327510993588141991264564812146530214503491136289085725
    pub const G2_GENERATOR_X_C0: Fq = MontFp!("96453755443802578867745476081903764610578492683850270111202389209355548711427786327510993588141991264564812146530214503491136289085725");

    /// G2_GENERATOR_X_C1 =
    /// 85346509177292795277012009839788781950274202400882571466460158277083221521663169974265433098009350061415973662678938824527658049065530
    pub const G2_GENERATOR_X_C1: Fq = MontFp!("85346509177292795277012009839788781950274202400882571466460158277083221521663169974265433098009350061415973662678938824527658049065530");

    /// G2_GENERATOR_Y_C0 =
    /// 49316184343270950587272132771103279293158283984999436491292404103501221698714795975575879957605051223501287444864258801515822358837529
    pub const G2_GENERATOR_Y_C0: Fq = MontFp!("49316184343270950587272132771103279293158283984999436491292404103501221698714795975575879957605051223501287444864258801515822358837529");

    /// G2_GENERATOR_Y_C1 =
    /// 107680854723992552431070996218129928499826544031468382031848626814251381379173928074140221537929995580031433096217223703806029068859074
    pub const G2_GENERATOR_Y_C1: Fq = MontFp!("107680854723992552431070996218129928499826544031468382031848626814251381379173928074140221537929995580031433096217223703806029068859074");
}
