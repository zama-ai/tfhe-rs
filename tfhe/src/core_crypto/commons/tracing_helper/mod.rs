use crate::core_crypto::commons::ciphertext_modulus::CiphertextModulus;
use crate::core_crypto::commons::traits::{Container, UnsignedInteger};

pub struct EntityMemoryTracer {
    type_name: String,
    /// Metadata provided by the object being traced.
    /// This field is optional to give the ability for a developer to only print the metadata when
    /// relevant, e.g. once before a loop instead of repeating it every iteration of a loop.
    metadata: Vec<Box<dyn core::fmt::Debug>>,
    /// The underlying memory of the object being traced.
    /// In case of particular encodings (e.g. power of two modular values being represented on the
    /// MSBs), these values can be pre-processed by the object being traced to have a user friendly
    /// print.
    data: Vec<u128>,
    /// How many bits in each u128 held by data are actually filled
    data_width: u32,
}

pub enum TracingAlignmentInfo {
    LSB,
    Unknown,
}

impl core::fmt::Debug for TracingAlignmentInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LSB => write!(f, "LSB-aligned data"),
            Self::Unknown => write!(f, "Unknown modulus/alignment"),
        }
    }
}

impl EntityMemoryTracer {
    pub fn new<S: ToString, T: UnsignedInteger, C: Container<Element = T>>(
        type_name: S,
        metadata: Option<Vec<Box<dyn core::fmt::Debug>>>,
        data: C,
        modulus: Option<CiphertextModulus<T>>,
    ) -> Self {
        let data = data.as_ref();

        let mut metadata = metadata.unwrap_or_else(|| vec![]);

        let (data, data_width) = if let Some(modulus) = modulus {
            // we have a modulus, so we pre-process the data to be LSB aligned
            metadata.push(Box::new(TracingAlignmentInfo::LSB));

            let data_width = modulus.into_modulus_log().0 as u32;

            if modulus.is_power_of_two() {
                (
                    data.iter()
                        .copied()
                        .map(|x| {
                            let x_u128: u128 = x.cast_into();
                            x_u128 >> (T::BITS - data_width as usize)
                        })
                        .collect(),
                    data_width,
                )
            } else {
                // Non native modulus, the data is already LSB aligned
                (
                    data.iter().copied().map(|x| x.cast_into()).collect(),
                    data_width,
                )
            }
        } else {
            metadata.push(Box::new(TracingAlignmentInfo::Unknown));
            (
                data.iter().copied().map(|x| x.cast_into()).collect(),
                T::BITS as u32,
            )
        };

        Self {
            type_name: type_name.to_string(),
            metadata,
            data,
            data_width,
        }
    }
}

impl core::fmt::Debug for EntityMemoryTracer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EntityMemoryTracer { ")?;
        write!(f, "type_name: {}", self.type_name)?;
        write!(f, ", metadata: {:?}", self.metadata)?;
        f.write_str(", data: ")?;

        if self.data.is_empty() {
            f.write_str("[]")?;
        } else {
            f.write_str("[")?;
            let (last, start) = self.data.split_last().expect("cannot fail");
            for x in start {
                write!(
                    f,
                    "0x{x:0width$x}, ",
                    width = 2 * self.data_width.div_ceil(8) as usize
                )?
            }
            write!(
                f,
                "0x{last:0width$x}",
                width = 2 * self.data_width.div_ceil(8) as usize
            )?;
            f.write_str("]")?;
        }
        f.write_str(" }")
    }
}
