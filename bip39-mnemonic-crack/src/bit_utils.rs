pub mod bit_utils {
    pub fn high_nbits(x: u32, bits: u32, bitlen: u32) -> u32 {
        x >> (bitlen - bits)
    }

    pub fn low_nbits(x: u32, bits: u32) -> u32 {
        x & ((1 << bits) - 1)
    }

    pub fn perm_to_bytearray(perm: &Vec<u32>) -> Vec<u8> {
        let mut result = vec![0; 16];
        result[0] = high_nbits(perm[0], 8, 11) as u8;
        result[1] = (low_nbits(perm[0], 3) << 5 | high_nbits(perm[1], 5, 11)) as u8;
        result[2] = (low_nbits(perm[1], 6) << 2 | high_nbits(perm[2], 2, 11)) as u8;
        result[3] = high_nbits(low_nbits(perm[2], 9), 8, 9) as u8;
        result[4] = (low_nbits(perm[2], 1) << 7 | high_nbits(perm[3], 7, 11)) as u8;
        result[5] = (low_nbits(perm[3], 4) << 4 | high_nbits(perm[4], 4, 11)) as u8;
        result[6] = (low_nbits(perm[4], 7) << 1 | high_nbits(perm[5], 1, 11)) as u8;
        result[7] = high_nbits(low_nbits(perm[5], 10), 8, 10) as u8;
        result[8] = (low_nbits(perm[5], 2) << 6 | high_nbits(perm[6], 6, 11)) as u8;
        result[9] = (low_nbits(perm[6], 5) << 3 | high_nbits(perm[7], 3, 11)) as u8;
        result[10] = low_nbits(perm[7], 8) as u8;
        result[11] = high_nbits(perm[8], 8, 11) as u8;
        result[12] = (low_nbits(perm[8], 3) << 5 | high_nbits(perm[9], 5, 11)) as u8;
        result[13] = (low_nbits(perm[9], 6) << 2 | high_nbits(perm[10], 2, 11)) as u8;
        result[14] = high_nbits(low_nbits(perm[10], 9), 8, 9) as u8;
        result[15] = (low_nbits(perm[10], 1) << 7 | high_nbits(perm[11], 7, 11)) as u8;
        result
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_high_nbits() {
            assert_eq!(high_nbits(0b101010, 3, 6), 0b101);
            assert_eq!(high_nbits(0b00101010, 3, 8), 0b001);
        }

        #[test]
        fn test_low_nbits() {
            assert_eq!(low_nbits(0b101010, 3), 0b010);
        }

        #[test]
        fn test_perm_to_bytearray() {
            let perm: Vec<u32> = vec![
                0b00000000000,
                0b00000000001,
                0b00000000010,
                0b00000000100,
                0b00000001000,
                0b00000010000,
                0b00000100000,
                0b00001000000,
                0b00010000000,
                0b00100000000,
                0b01000000000,
                0b10000000000,
            ];
            let bytearray = perm_to_bytearray(&perm);
            assert_eq!(
                bytearray,
                vec![
                    0b00000000, 0b00000000, 0b00000100, 0b00000001, 0b00000000, 0b01000000,
                    0b00010000, 0b00000100, 0b00000001, 0b00000000, 0b01000000, 0b00010000,
                    0b00000100, 0b00000001, 0b00000000, 0b01000000,
                ]
            );
        }
    }
}
