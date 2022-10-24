use super::{Cleartext, CleartextList, Plaintext, PlaintextList};
use crate::core_crypto::commons::math::decomposition::SignedDecomposer;
use crate::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor};
use crate::core_crypto::commons::math::torus::{FromTorus, IntoTorus, UnsignedTorus};
use crate::core_crypto::commons::numeric::{FloatingPoint, Numeric};
use crate::core_crypto::prelude::{DecompositionBaseLog, DecompositionLevelCount};
#[cfg(feature = "__commons_serialization")]
use serde::{Deserialize, Serialize};

/// A trait for types that encode cleartext to plaintext.
///
/// Examples use the [`RealEncoder'] type.
pub trait Encoder<Enc: Numeric> {
    /// The type of the cleartexts.
    type Raw: Numeric;

    /// Encodes a single cleartext.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::encoding::*;
    /// let encoder = RealEncoder {
    ///     offset: 1. as f32,
    ///     delta: 10.,
    /// };
    /// let cleartext = Cleartext(7. as f32);
    /// let encoded: Plaintext<u32> = encoder.encode(cleartext.clone());
    /// let decoded = encoder.decode(encoded);
    /// assert!((cleartext.0 - decoded.0).abs() < 0.1);
    /// ```
    fn encode(&self, raw: Cleartext<Self::Raw>) -> Plaintext<Enc>;

    /// Decodes a single encoded value.
    ///
    /// See [`Encoder::encode`] for an example.
    fn decode(&self, encoded: Plaintext<Enc>) -> Cleartext<Self::Raw>;

    /// Encodes a list of cleartexts to a list of plaintexts.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tfhe::core_crypto::commons::crypto::encoding::*;
    /// let encoder = RealEncoder {
    ///     offset: 1. as f32,
    ///     delta: 10.,
    /// };
    /// let clear_values = CleartextList::from_container(vec![7. as f32; 100]);
    /// let mut plain_values = PlaintextList::from_container(vec![0 as u32; 100]);
    /// encoder.encode_list(&mut plain_values, &clear_values);
    /// let mut decoded_values = CleartextList::from_container(vec![0. as f32; 100]);
    /// encoder.decode_list(&mut decoded_values, &plain_values);
    /// for (clear, decoded) in clear_values
    ///     .cleartext_iter()
    ///     .zip(decoded_values.cleartext_iter())
    /// {
    ///     assert!((clear.0 - decoded.0).abs() < 0.1);
    /// }
    /// ```
    fn encode_list<RawCont, EncCont>(
        &self,
        encoded: &mut PlaintextList<EncCont>,
        raw: &CleartextList<RawCont>,
    ) where
        CleartextList<RawCont>: AsRefTensor<Element = Self::Raw>,
        PlaintextList<EncCont>: AsMutTensor<Element = Enc>,
    {
        encoded
            .as_mut_tensor()
            .fill_with_one(raw.as_tensor(), |r| self.encode(Cleartext(*r)).0);
    }

    /// Decodes a list of plaintexts into a list of cleartexts.
    ///
    /// See [`Encoder::encode_list`] for an example.
    fn decode_list<RawCont, EncCont>(
        &self,
        raw: &mut CleartextList<RawCont>,
        encoded: &PlaintextList<EncCont>,
    ) where
        CleartextList<RawCont>: AsMutTensor<Element = Self::Raw>,
        PlaintextList<EncCont>: AsRefTensor<Element = Enc>,
    {
        raw.as_mut_tensor()
            .fill_with_one(encoded.as_tensor(), |e| self.decode(Plaintext(*e)).0);
    }
}

/// An encoder for real cleartexts
pub struct RealEncoder<T: FloatingPoint> {
    /// The offset of the encoding
    pub offset: T,
    /// The delta of the encoding
    pub delta: T,
}

impl<RawScalar, EncScalar> Encoder<EncScalar> for RealEncoder<RawScalar>
where
    EncScalar: UnsignedTorus + FromTorus<RawScalar> + IntoTorus<RawScalar>,
    RawScalar: FloatingPoint,
{
    type Raw = RawScalar;
    fn encode(&self, raw: Cleartext<RawScalar>) -> Plaintext<EncScalar> {
        Plaintext(<EncScalar as FromTorus<RawScalar>>::from_torus(
            (raw.0 - self.offset) / self.delta,
        ))
    }
    fn decode(&self, encoded: Plaintext<EncScalar>) -> Cleartext<RawScalar> {
        let mut e: RawScalar = encoded.0.into_torus();
        e *= self.delta;
        e += self.offset;
        Cleartext(e)
    }
}

/// The encoder originally used to encode f64 in the crypto api.
#[cfg_attr(feature = "__commons_serialization", derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq)]
pub struct FloatEncoder {
    pub(crate) o: f64,     // with margin between 1 and 0
    pub(crate) delta: f64, // with margin between 1 and 0
    pub(crate) nb_bit_precision: usize,
    pub(crate) nb_bit_padding: usize,
    pub(crate) round: bool,
}

impl FloatEncoder {
    fn new(min: f64, max: f64, nb_bit_precision: usize, nb_bit_padding: usize) -> FloatEncoder {
        if min >= max {
            panic!("Found min ({}) greater than max ({})", min, max);
        }
        if nb_bit_precision == 0 {
            panic!("Found 0 bits of precision. Should be strictly positive.");
        }

        let margin: f64 = (max - min) / (f64::powi(2., nb_bit_precision as i32) - 1.);

        FloatEncoder {
            o: min,
            delta: max - min + margin,
            nb_bit_precision,
            nb_bit_padding,
            round: false,
        }
    }

    fn new_rounding_context(
        min: f64,
        max: f64,
        nb_bit_precision: usize,
        nb_bit_padding: usize,
    ) -> FloatEncoder {
        if min >= max {
            panic!("Found min ({}) greater than max ({})", min, max);
        }
        if nb_bit_precision == 0 {
            panic!("Found 0 bits of precision. Should be strictly positive.");
        }

        let margin: f64 = (max - min) / (f64::powi(2., nb_bit_precision as i32) - 1.);

        FloatEncoder {
            o: min,
            delta: max - min + margin,
            nb_bit_precision,
            nb_bit_padding,
            round: true,
        }
    }

    fn new_centered(
        center: f64,
        radius: f64,
        nb_bit_precision: usize,
        nb_bit_padding: usize,
    ) -> FloatEncoder {
        if radius <= 0. {
            panic!("Found negative radius({})", radius);
        }
        if nb_bit_precision == 0 {
            panic!("Found 0 bits of precision. Should be strictly positive.");
        }
        FloatEncoder::new(
            center - radius,
            center + radius,
            nb_bit_precision,
            nb_bit_padding,
        )
    }

    fn zero() -> FloatEncoder {
        FloatEncoder {
            o: 0.,
            delta: 0.,
            nb_bit_precision: 0,
            nb_bit_padding: 0,
            round: false,
        }
    }

    fn get_granularity(&self) -> f64 {
        self.delta / f64::powi(2., self.nb_bit_precision as i32)
    }

    fn copy(&mut self, encoder: &FloatEncoder) {
        self.o = encoder.o;
        self.delta = encoder.delta;
        self.nb_bit_precision = encoder.nb_bit_precision;
        self.nb_bit_padding = encoder.nb_bit_padding;
    }

    fn is_valid(&self) -> bool {
        !(self.nb_bit_precision == 0 || self.delta <= 0.)
    }

    pub(crate) fn is_message_out_of_range(&self, message: f64) -> bool {
        message < self.o || message > self.o + self.delta
    }
}

impl<EncScalar> Encoder<EncScalar> for FloatEncoder
where
    EncScalar: UnsignedTorus + FromTorus<f64> + IntoTorus<f64>,
{
    type Raw = f64;

    fn encode(&self, raw: Cleartext<Self::Raw>) -> Plaintext<EncScalar> {
        if self.is_message_out_of_range(raw.0) {
            panic!(
                "Tried to encode a message ({}) outside of the encoder interval [{}, {}].",
                raw.0,
                self.o,
                self.o + self.delta
            );
        }
        if !self.is_valid() {
            panic!("Tried to encode a message with an invalid encoder.")
        }
        let mut res: EncScalar =
            <EncScalar as FromTorus<f64>>::from_torus((raw.0 - self.o) / self.delta);
        if self.round {
            let decomposer = SignedDecomposer::<EncScalar>::new(
                DecompositionBaseLog(self.nb_bit_precision),
                DecompositionLevelCount(1),
            );
            res = decomposer.closest_representable(res);
        }
        if self.nb_bit_padding > 0 {
            res >>= self.nb_bit_padding;
        }
        Plaintext(res)
    }

    fn decode(&self, encoded: Plaintext<EncScalar>) -> Cleartext<Self::Raw> {
        if !self.is_valid() {
            panic!("Tried to encode a message with an invalid encoder.")
        }
        let mut tmp: EncScalar = if self.round {
            let decomposer = SignedDecomposer::<EncScalar>::new(
                DecompositionBaseLog(self.nb_bit_precision + self.nb_bit_padding),
                DecompositionLevelCount(1),
            );
            decomposer.closest_representable(encoded.0)
        } else {
            encoded.0
        };

        // remove padding
        if self.nb_bit_padding > 0 {
            tmp <<= self.nb_bit_padding;
        }

        // round if round is set to false and if in the security margin
        let starting_value_security_margin: EncScalar =
            ((EncScalar::ONE << (self.nb_bit_precision + 1)) - EncScalar::ONE)
                << (<EncScalar as Numeric>::BITS - self.nb_bit_precision);
        let decomposer = SignedDecomposer::<EncScalar>::new(
            DecompositionBaseLog(self.nb_bit_precision),
            DecompositionLevelCount(1),
        );
        tmp = if tmp > starting_value_security_margin {
            decomposer.closest_representable(tmp)
        } else {
            tmp
        };

        let mut e: f64 = tmp.into_torus();
        e *= self.delta;
        e += self.o;
        Cleartext(e)
    }
}

#[cfg(all(test))]
mod test {
    #![allow(clippy::float_cmp)]

    use crate::core_crypto::commons::crypto::encoding::{
        Cleartext, CleartextList, Encoder, FloatEncoder, Plaintext, PlaintextList,
    };
    use crate::core_crypto::commons::math::random::RandomGenerator;
    use crate::core_crypto::commons::math::tensor::{AsMutTensor, AsRefTensor, Tensor};
    use crate::core_crypto::prelude::{CleartextCount, PlaintextCount};
    use concrete_csprng::generators::SoftwareRandomGenerator;
    use concrete_csprng::seeders::{Seeder, UnixSeeder};

    #[allow(unused_macros)]
    macro_rules! generate_random_interval {
        () => {{
            let mut seeder = UnixSeeder::new(0);
            let mut generator: RandomGenerator<SoftwareRandomGenerator> =
                RandomGenerator::new(seeder.seed());
            let coins: Vec<u32> = generator.random_uniform_tensor(3).into_container();

            let interval_type: usize = (coins[0] % 3) as usize;
            let interval_size = ((coins[1] % (1000 * 1000)) as f64) / 1000.;
            let interval_start = ((coins[2] % (1000 * 1000)) as f64) / 1000.;
            match interval_type {
                0 => {
                    // negative interval
                    (-interval_start - interval_size, -interval_start)
                }
                1 => {
                    // positive interval
                    (interval_start, interval_size + interval_start)
                }
                2 => {
                    // zero in the interval
                    let tmp = ((coins[2] % (1000 * 1000)) as f64) / (1000. * 1000.) * interval_size;
                    (-interval_size + tmp, tmp)
                }
                _ => (0., 0.),
            }
        }};
    }

    #[allow(unused_macros)]
    macro_rules! generate_precision_padding {
        ($max_precision: expr, $max_padding: expr) => {{
            let mut seeder = UnixSeeder::new(0);
            let mut generator: RandomGenerator<SoftwareRandomGenerator> =
                RandomGenerator::new(seeder.seed());
            let rs: Vec<u32> = generator.random_uniform_tensor(2).into_container();
            (
                ((rs[0] % $max_precision) as usize) + 1,
                (rs[1] % $max_padding) as usize,
            )
        }};
    }

    #[allow(unused_macros)]
    macro_rules! random_message {
        ($min: expr, $max: expr) => {{
            let mut seeder = UnixSeeder::new(0);
            let mut generator: RandomGenerator<SoftwareRandomGenerator> =
                RandomGenerator::new(seeder.seed());
            let rs: Vec<u64> = generator.random_uniform_tensor(1).into_container();
            (rs[0] as f64) / f64::powi(2., 64) * ($max - $min) + $min
        }};
    }

    #[allow(unused_macros)]
    macro_rules! assert_eq_granularity {
        ($A:expr, $B:expr, $ENC:expr) => {
            assert!(
                ($A - $B).abs() < $ENC.get_granularity(),
                "{} != {} +- {} (|delta|={})-> encoder: {:?}",
                $A,
                $B,
                $ENC.get_granularity(),
                ($A - $B).abs(),
                $ENC
            );
        };
    }

    #[allow(unused_macros)]
    macro_rules! random_index {
        ($max: expr) => {{
            if $max == 0 {
                (0 as usize)
            } else {
                let mut seeder = UnixSeeder::new(0);
                let mut generator: RandomGenerator<SoftwareRandomGenerator> =
                    RandomGenerator::new(seeder.seed());
                let rs: Vec<u32> = generator.random_uniform_tensor(1).into_container();
                (rs[0] % ($max as u32)) as usize
            }
        }};
    }

    #[allow(unused_macros)]
    macro_rules! random_messages {
        ($min: expr, $max: expr, $nb: expr) => {{
            let mut res = vec![0 as f64; $nb];
            for r in res.iter_mut() {
                *r = random_message!($min, $max);
            }
            res
        }};
    }

    #[test]
    fn test_new_x_encode_single_x_decode_single() {
        // random settings
        let (min, max) = generate_random_interval!();
        let (precision, padding) = generate_precision_padding!(8, 8);

        // generates a random message
        let m: f64 = random_message!(min, max);

        // create an encoder
        let encoder = FloatEncoder::new(min, max, precision, padding);

        // encode and decode
        let plaintext: Plaintext<u64> = encoder.encode(Cleartext(m));
        let decoding = encoder.decode(plaintext);

        // test
        assert_eq_granularity!(m, decoding.0, encoder);
    }

    #[test]
    fn test_new_centered_x_encode_single_x_decode_single() {
        // random settings
        let (min, max) = generate_random_interval!();
        let (precision, padding) = generate_precision_padding!(8, 8);

        // generates a random message
        let m: f64 = random_message!(min, max);

        // create an encoder
        let encoder = FloatEncoder::new_centered(
            min + (max - min) / 2.,
            (max - min) / 2.,
            precision,
            padding,
        );

        // encode and decode
        let plaintext: Plaintext<u64> = encoder.encode(Cleartext(m));
        let decoding = encoder.decode(plaintext);

        // test
        assert_eq_granularity!(m, decoding.0, encoder);
    }

    #[test]
    fn test_new_x_is_valid() {
        // random settings
        let (min, max) = generate_random_interval!();
        let (precision, padding) = generate_precision_padding!(8, 8);

        // create an encoder
        let encoder = FloatEncoder::new(min, max, precision, padding);

        //test
        assert!(encoder.is_valid());
    }

    #[test]
    fn test_new_centered_x_is_valid() {
        // random settings
        let (min, max) = generate_random_interval!();
        let (precision, padding) = generate_precision_padding!(8, 8);

        // create an encoder
        let encoder = FloatEncoder::new_centered(
            min + (max - min) / 2.,
            (max - min) / 2.,
            precision,
            padding,
        );

        //test
        assert!(encoder.is_valid());
    }

    #[test]
    fn test_zero_x_is_valid() {
        // create a zero encoder
        let encoder = FloatEncoder::zero();

        //test
        assert!(!encoder.is_valid());
    }

    #[test]
    fn test_new_x_encode() {
        let nb_messages: usize = 10;

        // random settings
        let (min, max) = generate_random_interval!();
        let (precision, padding) = generate_precision_padding!(8, 8);

        // generates a random message
        let messages: Vec<f64> = random_messages!(min, max, nb_messages);

        // create an encoder
        let encoder = FloatEncoder::new(min, max, precision, padding);

        let input_cleartext = CleartextList::from_container(messages.as_slice());
        let mut plaintext_list = PlaintextList::allocate(0u64, PlaintextCount(nb_messages));
        let mut output_cleartext = CleartextList::allocate(0.0f64, CleartextCount(nb_messages));

        // encode and decode
        encoder.encode_list(&mut plaintext_list, &input_cleartext);
        encoder.decode_list(&mut output_cleartext, &plaintext_list);

        // test
        for (m, d) in messages.iter().zip(output_cleartext.cleartext_iter()) {
            assert_eq_granularity!(m, d.0, encoder);
        }
    }

    #[test]
    fn test_new_x_encode_single_x_copy_x_decode_single() {
        // create a first encoder
        let (min, max) = generate_random_interval!();
        let (precision, padding) = generate_precision_padding!(8, 8);
        let encoder = FloatEncoder::new(min, max, precision, padding);

        // generates a random message
        let m: f64 = random_message!(min, max);

        // create a second encoder
        let (min, max) = generate_random_interval!();
        let (precision, padding) = generate_precision_padding!(8, 8);
        let mut encoder_copy = FloatEncoder::new(min, max, precision, padding);

        // copy the encoder
        encoder_copy.copy(&encoder);

        // encode and decode
        let plaintext: Plaintext<u64> = encoder.encode(Cleartext(m));
        let decoding = encoder_copy.decode(plaintext);

        // tests
        assert_eq_granularity!(m, decoding.0, encoder);
        assert_eq!(encoder, encoder_copy);
    }

    #[test]
    fn test_new_rounding_context_x_encode_single_x_decode_single() {
        // create an encoder with a granularity = 1
        let (min, _) = generate_random_interval!();
        let (precision, padding) = generate_precision_padding!(8, 8);
        let max = min + f64::powi(2., precision as i32) - 1.;
        let encoder = FloatEncoder::new_rounding_context(min, max, precision, padding);

        for _ in 0..100 {
            // generates a random message
            let m: f64 = random_index!((f64::powi(2., precision as i32)) as usize) as f64; // [0,2**prec[ + min
            let m1 = m + min;

            // encode and decode
            let plaintext: Plaintext<u64> = encoder.encode(Cleartext(m1));
            let decoding = encoder.decode(plaintext);

            // message with error in [-0.5,0.5]
            let m2: f64 = m1
                + if m == 0. {
                    random_message!(0., 0.5)
                } else {
                    random_message!(-0.5, 0.5)
                };

            // encode and decode
            let plaintext2: Plaintext<u64> = encoder.encode(Cleartext(m2));
            let decoding2 = encoder.decode(plaintext2);

            // tests
            assert_eq!(m1, decoding.0);
            assert_eq!(m1, decoding2.0);
        }
    }

    #[test]
    fn margins_with_integers() {
        let power: usize = random_index!(5) + 2;
        let nb_messages: usize = (1 << power) - 1;
        let min = 0.;
        let max = f64::powi(2., power as i32) - 1.;
        let padding = random_index!(8);

        // generates a random message
        let mut messages: Vec<f64> = vec![0.; nb_messages];
        for (i, m) in messages.iter_mut().enumerate() {
            *m = i as f64;
        }

        // create an encoder
        let encoder = FloatEncoder::new(min, max, power, padding);
        let encoder_round = FloatEncoder::new_rounding_context(min, max, power, padding);

        // encode
        let mut plaintext = PlaintextList::allocate(0u64, PlaintextCount(nb_messages));
        encoder_round.encode_list(
            &mut plaintext,
            &CleartextList::from_container(messages.as_slice()),
        );

        // add some error
        let random_errors = random_messages!(0., 0.5, nb_messages);
        let mut plaintext_error = PlaintextList::allocate(0u64, PlaintextCount(nb_messages));
        encoder.encode_list(
            &mut plaintext_error,
            &CleartextList::from_container(random_errors.as_slice()),
        );
        plaintext
            .as_mut_tensor()
            .update_with_wrapping_add(plaintext_error.as_tensor());

        // decode
        let mut decoding = CleartextList::allocate(0.0f64, CleartextCount(nb_messages));
        encoder_round.decode_list(&mut decoding, &plaintext);

        // test
        for ((m, d), e) in messages
            .iter()
            .zip(decoding.cleartext_iter())
            .zip(random_errors.iter())
        {
            println!("m {} d {} e {} ", m, d.0, e);
            assert_eq!(*m, d.0);
        }

        // encode
        let mut plaintext = PlaintextList::allocate(0u64, PlaintextCount(nb_messages));
        encoder_round.encode_list(
            &mut plaintext,
            &CleartextList::from_container(messages.as_slice()),
        );

        // add some error
        let random_errors = random_messages!(0., 0.5, nb_messages);
        let mut plaintext_error = PlaintextList::allocate(0u64, PlaintextCount(nb_messages));
        encoder.encode_list(
            &mut plaintext_error,
            &CleartextList::from_container(random_errors.as_slice()),
        );
        plaintext
            .as_mut_tensor()
            .update_with_wrapping_add(plaintext_error.as_tensor());

        // decode
        let mut decoding = CleartextList::allocate(0.0f64, CleartextCount(nb_messages));
        encoder_round.decode_list(&mut decoding, &plaintext);

        // test
        for ((m, d), e) in messages
            .iter()
            .zip(decoding.cleartext_iter())
            .zip(random_errors.iter())
        {
            println!("m {} d {} e {} ", m, d.0, e);
            assert_eq!(*m, d.0);
        }
    }

    #[test]
    fn margins_with_reals() {
        let nb_messages: usize = 400;
        let (min, max) = generate_random_interval!();
        let padding = random_index!(3);
        let precision = random_index!(3) + 2;

        // generates a random message

        let mut messages: Vec<f64> = random_messages!(min, max, nb_messages);
        messages[0] = min;
        messages[1] = max;

        // create an encoder
        let encoder = FloatEncoder::new(min, max, precision, padding);

        // encode
        let mut plaintext = PlaintextList::allocate(0u64, PlaintextCount(nb_messages));
        encoder.encode_list(
            &mut plaintext,
            &CleartextList::from_container(messages.as_slice()),
        );

        // add some error
        let mut seeder = UnixSeeder::new(0);
        let mut generator: RandomGenerator<SoftwareRandomGenerator> =
            RandomGenerator::new(seeder.seed());
        let random_errors: Tensor<Vec<u64>> =
            generator.random_gaussian_tensor(nb_messages, 0., f64::powi(2., -25));
        plaintext
            .as_mut_tensor()
            .update_with_wrapping_add(&random_errors);

        // decode
        let mut decoding = CleartextList::allocate(0.0f64, CleartextCount(nb_messages));
        encoder.decode_list(&mut decoding, &plaintext);

        // test
        for (m, d) in messages.iter().zip(decoding.cleartext_iter()) {
            assert!(
                f64::abs(m - d.0) <= encoder.get_granularity(),
                "error: m {} d {} ",
                m,
                d.0
            );
        }
    }
}
