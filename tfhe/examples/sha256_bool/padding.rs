// This module contains the padding function, which is computed by the client over the plain text.
// The function returns the padded data as a vector of bools, for later encryption. Note that
// padding could also be performed by the server, by appending trivially encrypted bools. However,
// in our implementation, the exact length of the pre-image (hashed message) is not revealed.

// If input starts with "0x" and following characters are valid hexadecimal values, it's interpreted
// as hex, otherwise input is interpreted as text
pub fn pad_sha256_input(input: &str) -> Vec<bool> {
    let bytes = if input.starts_with("0x") && is_valid_hex(&input[2..]) {
        let no_prefix = &input[2..];
        let hex_input = if no_prefix.len() % 2 == 0 {
            // hex value can be converted to bytes
            no_prefix.to_string()
        } else {
            format!("0{}", no_prefix) // pad hex value to ensure a correct conversion to bytes
        };
        hex_input
            .as_bytes()
            .chunks(2)
            .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
            .collect::<Vec<u8>>()
    } else {
        input.as_bytes().to_vec()
    };

    pad_sha256_data(&bytes)
}

fn is_valid_hex(hex: &str) -> bool {
    hex.chars().all(|c| c.is_ascii_hexdigit())
}

fn pad_sha256_data(data: &[u8]) -> Vec<bool> {
    let mut bits: Vec<bool> = data
        .iter()
        .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
        .collect();

    // Append a single '1' bit
    bits.push(true);

    // Calculate the number of padding zeros required
    let padding_zeros = (512 - ((bits.len() + 64) % 512)) % 512;
    bits.extend(std::iter::repeat(false).take(padding_zeros));

    // Append a 64-bit big-endian representation of the original message length
    let data_len_bits = (data.len() as u64) * 8;
    bits.extend((0..64).rev().map(|i| (data_len_bits >> i) & 1 == 1));

    bits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256_function::bools_to_hex;

    #[test]
    fn test_pad_sha256_input() {
        let input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let expected_output = "6162636462636465636465666465666765666768666768696768696a68696a6\
        b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f70718000000000000000000000000000000000000000000\
        000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c0";

        let result = pad_sha256_input(input);
        let hex_result = bools_to_hex(result);

        assert_eq!(hex_result, expected_output);
    }
}
