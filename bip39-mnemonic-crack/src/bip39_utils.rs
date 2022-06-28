pub mod bip39_utils {
    use std::collections::HashMap;

    use hmac::Hmac;
    use pbkdf2::pbkdf2;
    use sha2::{Digest, Sha256, Sha512};

    pub fn sentence_checksum(bytearray: &[u8; 16]) -> u8 {
        let mut hasher = Sha256::new();
        hasher.update(bytearray);
        let digest = hasher.finalize();
        digest[0] >> 4
    }

    pub fn indices_to_sentence(
        word_indices: &[u32; 12],
        dictionary: &HashMap<u32, String>,
    ) -> String {
        word_indices
            .iter()
            .map(|x| dictionary[x].clone())
            .collect::<Vec<String>>()
            .join(" ")
    }

    pub fn mnemonic_to_seed_with_passphrase(sentence: &str, passphrase: &str) -> [u8; 64] {
        let mut derived_key = [0; 64];
        pbkdf2::<Hmac<Sha512>>(
            sentence.as_bytes(),
            ("mnemonic".to_owned() + passphrase).as_bytes(),
            2048,
            &mut derived_key,
        );
        derived_key
    }

    pub fn mnemonic_to_seed(sentence: &str) -> [u8; 64] {
        let mut derived_key = [0; 64];
        pbkdf2::<Hmac<Sha512>>(
            sentence.as_bytes(),
            "mnemonic".as_bytes(),
            2048,
            &mut derived_key,
        );
        derived_key
    }

    #[cfg(test)]
    mod tests {
        use hex_literal::hex;

        use crate::bit_utils::bit_utils::low_nbits;

        use super::*;

        #[test]
        fn test_slice_comparision() {
            let vec1 = vec![0, 1, 2, 3];
            let vec2 = vec![2, 3];
            assert!(vec1[2..] == vec2[..]);
            assert_eq!(vec1[2..], vec2[..]);
            assert_ne!(vec1[..], vec2[..]);
        }

        #[test]
        fn test_sentence_checksum() {
            assert_eq!(
                sentence_checksum(&hex!("00000000000000000000000000000000")),
                low_nbits(3, 4) as u8 // about
            );
            assert_eq!(
                sentence_checksum(&hex!("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f")),
                low_nbits(2040, 4) as u8 // yellow
            );
            assert_eq!(
                sentence_checksum(&hex!("80808080808080808080808080808080")),
                low_nbits(4, 4) as u8 // above
            );
            assert_eq!(
                sentence_checksum(&hex!("ffffffffffffffffffffffffffffffff")),
                low_nbits(2037, 4) as u8 // wrong
            );
        }

        #[test]
        fn test_mnemonic_to_seed() {
            assert_eq!(
                mnemonic_to_seed_with_passphrase("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "TREZOR"),
                hex!("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")
            );
            assert_eq!(
                mnemonic_to_seed_with_passphrase("legal winner thank year wave sausage worth useful legal winner thank yellow", "TREZOR"),
                hex!("2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607")
            );
            assert_eq!(
                mnemonic_to_seed_with_passphrase("letter advice cage absurd amount doctor acoustic avoid letter advice cage above", "TREZOR"),
                hex!("d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8")
            );
            assert_eq!(
                mnemonic_to_seed_with_passphrase("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong", "TREZOR"),
                hex!("ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069")
            );
        }
    }
}
