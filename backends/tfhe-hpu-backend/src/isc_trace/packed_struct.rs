use bitvec::prelude::*;
use std::error::Error;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};

/// Macro used to define packed struct
macro_rules! integer_packed_struct {
    ($x: ident) => {
        impl<O> PackedStructLsb<O> for $x
        where
            O: bitvec::store::BitStore,
        {
            fn from_bit_slice_le(slice: &BitSlice<O, Lsb0>) -> Result<Self, Box<dyn Error>> {
                if slice.len() != 0 {
                    Ok(slice[0..($x::BITS as usize).min(slice.len())].load::<$x>())
                } else {
                    Err(NoMoreBits)?
                }
            }
            fn to_bit_slice_le(&self, dst: &mut BitSlice<O, Lsb0>) -> Result<(), Box<dyn Error>> {
                if dst.len() == 0 {
                    Err(NoMoreBits)?
                } else {
                    let size = dst.len().min($x::len());
                    dst[0..size].clone_from_bitslice(&self.try_view_bits::<Lsb0>()?[0..size]);
                    Ok(())
                }
            }
        }

        impl Len for $x {
            fn len() -> usize {
                $x::BITS as usize
            }
        }
    };
}

#[derive(Debug)]
pub struct NoMoreBits;

impl Error for NoMoreBits {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }

    fn description(&self) -> &str {
        "No more bits to unpack"
    }
}

impl Display for NoMoreBits {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

pub trait Len {
    fn len() -> usize;
}

pub trait PackedStructLsb<O>
where
    O: bitvec::store::BitStore,
    Self: Sized + Len,
{
    fn from_bit_slice_le(slice: &BitSlice<O, Lsb0>) -> Result<Self, Box<dyn Error>>;
    fn to_bit_slice_le(&self, _dst: &mut BitSlice<O, Lsb0>) -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}

impl Len for bool {
    fn len() -> usize {
        1
    }
}

impl<O> PackedStructLsb<O> for bool
where
    O: bitvec::store::BitStore,
{
    fn from_bit_slice_le(slice: &BitSlice<O, Lsb0>) -> Result<Self, Box<dyn Error>> {
        if slice.len() != 0 {
            Ok(slice[0])
        } else {
            Err(NoMoreBits)?
        }
    }
    fn to_bit_slice_le(&self, dst: &mut BitSlice<O, Lsb0>) -> Result<(), Box<dyn Error>> {
        if dst.len() > bool::len() {
            Err(NoMoreBits)?
        } else {
            dst.set(0, *self);
            Ok(())
        }
    }
}

integer_packed_struct!(u8);
integer_packed_struct!(u16);
integer_packed_struct!(u32);
integer_packed_struct!(u64);

#[cfg(test)]
mod packed_struct_tests {
    use super::*;

    #[test]
    fn simple() {
        let mut bytes: [u8; 3] = [0x00, 0x00, 0x00];
        let out_view = bytes.view_bits_mut::<Lsb0>();

        let byte0: u8 = 0xFF;
        let byte1: u8 = 0x00;
        let byte2: u8 = 0xF0;

        byte0.to_bit_slice_le(&mut out_view[0..7]).unwrap();
        byte1.to_bit_slice_le(&mut out_view[7..15]).unwrap();
        byte2.to_bit_slice_le(&mut out_view[15..23]).unwrap();

        print!("Struct partially deserialized 0x{:?}\n", bytes);

        let bytes: [u8; 3] = [0xBA, 0xBE, 0x12];
        let mut view = bytes.view_bits::<Lsb0>();

        for _ in bytes {
            print!("next u8: {:X}\n", u8::from_bit_slice_le(&view).unwrap());
            view = &view[u8::len()..];
        }
    }

    #[test]
    fn bitvec() {
        use bitvec::prelude::*;

        let raw = [
            0x8_Fu8,
            //  7 0
            0x0_1u8,
            // 15 8
            0b1111_0010u8,
            //       ^ sign bit
            // 23       16
        ];
        let asd = &raw.view_bits::<Lsb0>()[4..20];
        assert_eq!(asd.load_le::<u16>(), 0x2018u16,);
    }
}
