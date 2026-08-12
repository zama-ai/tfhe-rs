use std::{iter::Peekable, str::FromStr};

use crate::{Backend, BenchmarkMetric, OperandType};

pub(crate) trait OptionalSegment:
    Sized + FromStr + PartialEq + Into<&'static str> + Copy
{
    const OMITTED_VARIANT: Self;

    fn segment(&self) -> Option<&'static str> {
        (*self != Self::OMITTED_VARIANT).then(|| (*self).into())
    }

    fn from_segment(s: &str) -> Option<Self> {
        s.parse().ok().filter(|v| v != &Self::OMITTED_VARIANT)
    }
}

pub(crate) fn next_segment<'a, T: OptionalSegment>(
    it: &mut Peekable<impl Iterator<Item = &'a str>>,
) -> Option<T> {
    let value = T::from_segment(it.peek()?)?;
    it.next();
    Some(value)
}

impl OptionalSegment for Backend {
    const OMITTED_VARIANT: Self = Backend::Cpu;
}

impl OptionalSegment for OperandType {
    const OMITTED_VARIANT: Self = OperandType::CipherText;
}

impl OptionalSegment for BenchmarkMetric {
    const OMITTED_VARIANT: Self = BenchmarkMetric::Latency;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the vocabulary to literal strings.
    ///
    /// `segment_roundtrip` cannot do this on its own: both directions read the
    /// same `#[strum]` attribute, so dropping `serialize_all` renames every
    /// segment while keeping the round-trip perfect.
    #[test]
    fn segments_are_spelled_as_the_grammar_writes_them() {
        assert_eq!(Backend::Cpu.segment(), None);
        assert_eq!(Backend::Cuda.segment(), Some("cuda"));
        assert_eq!(Backend::Hpu.segment(), Some("hpu"));

        assert_eq!(BenchmarkMetric::Latency.segment(), None);
        assert_eq!(BenchmarkMetric::Throughput.segment(), Some("throughput"));
        assert_eq!(BenchmarkMetric::PbsCount.segment(), Some("pbs_count"));
        assert_eq!(BenchmarkMetric::KeySize.segment(), Some("key_size"));

        assert_eq!(OperandType::CipherText.segment(), None);
        assert_eq!(OperandType::PlainText.segment(), Some("scalar"));
    }

    /// The omitted variant must not parse as a segment. `Display` never writes
    /// it, so accepting it would give the same spec two spellings.
    #[test]
    fn omitted_variants_are_not_segments() {
        assert_eq!(Backend::from_segment("cpu"), None);
        assert_eq!(BenchmarkMetric::from_segment("latency"), None);
        assert_eq!(OperandType::from_segment("cipher_text"), None);
    }

    #[test]
    fn segment_roundtrip() {
        fn check<T>(variants: &[T])
        where
            T: OptionalSegment + Copy + PartialEq + std::fmt::Debug,
        {
            for &variant in variants {
                if let Some(segment) = variant.segment() {
                    assert_eq!(T::from_segment(segment), Some(variant), "{segment:?}");
                }
            }
        }

        check(&[Backend::Cpu, Backend::Cuda, Backend::Hpu]);
        check(&[
            BenchmarkMetric::Latency,
            BenchmarkMetric::Throughput,
            BenchmarkMetric::PbsCount,
            BenchmarkMetric::KeySize,
        ]);
        check(&[OperandType::CipherText, OperandType::PlainText]);
    }
}
