use crate::core_crypto::commons::traits::{AsMemoryTracer, Container, UnsignedInteger};

pub struct EntityMemoryTracer {
    type_name: String,
    /// Metadata provided by the object being traced.
    /// This field is optional to give the ability for a developer to only print the metadata when
    /// relevant, e.g. once before a loop instead of repeating it every iteration of a loop.
    metadata: Option<Vec<Box<dyn core::fmt::Debug>>>,
    /// The underlying memory of the object being traced.
    /// In case of particular encodings (e.g. power of two modular values being represented on the
    /// MSBs), these values can be pre-processed by the object being traced to have a user friendly
    /// print.
    data: Vec<u128>,
    /// How many bits in each u128 held by data are actually filled
    data_width: u32,
}

impl EntityMemoryTracer {
    pub fn new<S: ToString>(
        type_name: S,
        metadata: Option<Vec<Box<dyn core::fmt::Debug>>>,
        data: Vec<u128>,
        data_width: u32,
    ) -> Self {
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
                    width = self.data_width.div_ceil(8) as usize
                )?
            }
            write!(
                f,
                "0x{last:0width$x}",
                width = self.data_width.div_ceil(8) as usize
            )?;
            f.write_str("]")?;
        }
        f.write_str(" }")
    }
}

impl<T, C> AsMemoryTracer for C
where
    T: UnsignedInteger,
    C: Container<Element = T>,
{
    fn as_memory_tracer(&self, with_metadata: bool) -> EntityMemoryTracer {
        let metadata: Option<Vec<Box<dyn core::fmt::Debug>>> = if with_metadata {
            Some(vec![Box::new(
                "TFHE-rs aligned (MSB power of 2, LSB otherwise)",
            )])
        } else {
            None
        };

        let data = self
            .as_ref()
            .iter()
            .copied()
            .map(|x| x.cast_into())
            .collect();

        EntityMemoryTracer::new(
            format!("[{}]", std::any::type_name::<T>()),
            metadata,
            data,
            T::BITS as u32,
        )
    }
}
