use itertools::Itertools;
use sha2::{Digest, Sha256};

fn high_nbits(x: u32, bits: u32) -> u32 {
    x >> (11 - bits)
}

fn low_nbits(x: u32, bits: u32) -> u32 {
    x & ((1 << bits) - 1)
}

fn perm_to_bytearray(perm: &Vec<u32>) -> Vec<u8> {
    let mut result = vec![];
    result.push(high_nbits(perm[0], 8) as u8);
    result.push((low_nbits(perm[0], 3) << 5 | high_nbits(perm[1], 5)) as u8);
    result.push((low_nbits(perm[1], 6) << 2 | high_nbits(perm[2], 2)) as u8);
    result.push((low_nbits(perm[2], 9) >> 1) as u8);
    result.push((low_nbits(perm[2], 1) << 7 | high_nbits(perm[3], 7)) as u8);
    result.push((low_nbits(perm[3], 4) << 4 | high_nbits(perm[4], 4)) as u8);
    result.push((low_nbits(perm[4], 7) << 1 | high_nbits(perm[5], 1)) as u8);
    result.push((low_nbits(perm[5], 10) >> 2) as u8);
    result.push((low_nbits(perm[5], 2) << 6 | high_nbits(perm[6], 6)) as u8);
    result.push((low_nbits(perm[6], 5) << 3 | high_nbits(perm[7], 3)) as u8);
    result.push(low_nbits(perm[7], 8) as u8);
    result.push(high_nbits(perm[8], 8) as u8);
    result.push((low_nbits(perm[8], 3) << 5 | high_nbits(perm[9], 5)) as u8);
    result.push((low_nbits(perm[9], 6) << 2 | high_nbits(perm[10], 2)) as u8);
    result.push((low_nbits(perm[10], 9) >> 1) as u8);
    result.push((low_nbits(perm[10], 1) << 7 | high_nbits(perm[11], 7)) as u8);
    result
}

fn main() {
    let wordlist_indices: Vec<u32> = vec![
        0, 224, 248, 365, 958, 964, 1033, 1114, 1156, 1798, 1293, 1358, 1401, 1354, 2047,
    ];
    for perm in wordlist_indices.into_iter().permutations(12) {
        let mut hasher = Sha256::new();
        let bytearray = perm_to_bytearray(&perm);
        hasher.update(bytearray);
        let digest = hasher.finalize();
        if (digest[0] >> 4) == low_nbits(perm[11], 4) as u8 {
            println!("Match found: {:?}", perm);
        }
    }
}
