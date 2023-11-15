use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
pub struct RadixDecomposition {
    pub msg_space: usize,
    pub block_number: usize,
}

/// Computes possible radix decompositions
///
/// Takes the number of bit of the message space as input and output a vector containing all the
/// correct
/// possible block decomposition assuming the same message space for all blocks.
/// Lower and upper bounds define the minimal and maximal space to be considered
/// Example: 6,2,4 -> [ [2,3], [3,2]] : [msg_space = 2 bits, block_number = 3]
///
/// # Example
///
/// ```rust
/// use concrete_float::client_key::radix_decomposition;
/// let input_space = 16; //
/// let min = 2;
/// let max = 4;
/// let decomp = radix_decomposition(input_space, min, max);
///
/// // Check that 3 possible radix decompositions are provided
/// assert_eq!(decomp.len(), 3);
/// ```
pub fn radix_decomposition(
    input_space: usize,
    min_space: usize,
    max_space: usize,
) -> Vec<RadixDecomposition> {
    let mut out: Vec<RadixDecomposition> = vec![];
    let mut max = max_space;
    if max_space > input_space {
        max = input_space;
    }
    for msg_space in min_space..max + 1 {
        let mut block_number = input_space / msg_space;
        //Manual ceil of the division
        if input_space % msg_space != 0 {
            block_number += 1;
        }
        out.push(RadixDecomposition {
            msg_space,
            block_number,
        })
    }
    out
}
