#[macro_export]
macro_rules! integer_packed_struct {
    ($x: ident) => 
        {
            impl <O> PackedStructLsb<O> for $x 
            where O: bitvec::store::BitStore
            {
                fn from_bit_slice_le(slice: &BitSlice<O,Lsb0>) -> 
                    Result<Self, Box<dyn Error>> {
                        if slice.len() != 0 {
                            Ok(slice[0..($x::BITS as usize).min(slice.len())]
                                .load::<$x>())
                        } else {
                            Err(NoMoreBits)?
                        }
                    }
                fn to_bit_slice_le(&self, dst: &mut BitSlice<O,Lsb0>) ->
                    Result<(), Box<dyn Error>> {
                        if dst.len() == 0 {
                            Err(NoMoreBits)?
                        } else {
                            let size = dst.len().min($x::len());
                            dst[0..size].clone_from_bitslice(
                                &self.try_view_bits::<Lsb0>()?[0..size]);
                            Ok(())
                        }
                }
            }

            impl Len for $x {
                fn len() -> usize {
                    $x::BITS as usize
                }
            }
        }
}

#[macro_export]
macro_rules! integer_len {
    ($x: ident) => {
    }
}
