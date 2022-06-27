use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufRead, BufReader, Write},
};

use clap::Parser;
use hmac::{Hmac, Mac};
use itertools::Itertools;
use pbkdf2::pbkdf2;
use sha2::{Digest, Sha256, Sha512};
use time::{format_description::well_known::Iso8601, OffsetDateTime};
use tokio::{fs::File as TokioFile, io::AsyncWriteExt};

macro_rules! async_writeln {
    ($dst: expr) => {
        {
            AsyncWriteExt::write_all(&mut $dst, b"\n").await
        }
    };
    ($dst: expr, $fmt: expr) => {
        {
            let mut buf = Vec::<u8>::new();
            writeln!(buf, $fmt)?;
            AsyncWriteExt::write_all(&mut $dst, &buf).await
        }
    };
    ($dst: expr, $fmt: expr, $($arg: tt)*) => {
        {
            let mut buf = Vec::<u8>::new();
            writeln!(buf, $fmt, $( $arg )*)?;
            AsyncWriteExt::write_all(&mut $dst, &buf).await
        }
    };
}

#[derive(Parser, Debug)]
#[clap(version)]
struct Args {
    /// Number of threads for hash calculation
    #[clap(short, long, value_parser, default_value_t = 1)]
    thread_count: u32,

    /// Path to dictionary file
    #[clap(long, value_parser, default_value = "dict.txt")]
    dict_file: String,

    /// Path to index file
    #[clap(long, value_parser, default_value = "index.txt")]
    index_file: String,

    /// Path to partial digest file
    #[clap(long, value_parser, default_value = "digest.txt")]
    digest_file: String,

    /// Path to output file
    #[clap(short, long, value_parser, default_value = "result.txt")]
    output_file: String,

    /// Maximum tries count. (all permutations are tried if set to -1)
    #[clap(long, value_parser, default_value_t = -1)]
    max_tries: i64,
}

fn high_nbits(x: u32, bits: u32, bitlen: u32) -> u32 {
    x >> (bitlen - bits)
}

fn low_nbits(x: u32, bits: u32) -> u32 {
    x & ((1 << bits) - 1)
}

fn perm_to_bytearray(perm: &Vec<u32>) -> Vec<u8> {
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

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();
    let mut output_file = TokioFile::create(args.output_file)
        .await
        .expect("Could not create output file");

    let dict_file = File::open(args.dict_file).expect("Could not open dictionary file");
    let mut dictionary = HashMap::new();
    for line in BufReader::new(dict_file).lines() {
        let line_unwrapped = line.expect("Could not read a dictionary word");
        let fields = line_unwrapped
            .split(" ")
            .map(|x| x.to_owned())
            .collect::<Vec<_>>();
        dictionary.insert(
            fields[0]
                .clone()
                .parse::<u32>()
                .expect("Could not parse word index"),
            fields[1].clone(),
        );
    }
    assert!(
        dictionary.len() >= 12,
        "Dictionary should contain at least 12 words."
    );
    println!("Dictionary contains {} words.", dictionary.len());

    let index_file = File::open(args.index_file).expect("Could not open index file");
    let mut indices = vec![];
    for line in BufReader::new(index_file).lines() {
        let tuple = line
            .expect("Could not read a line from index file")
            .split(" ")
            .map(|x| x.parse::<u32>().expect("Could not parse an index"))
            .collect::<Vec<_>>();
        assert!(
            tuple.len() == 12,
            "The index file should contain one 12-tuple per line."
        );
        indices.push(tuple);
    }
    println!("Index file contains {} 12-tuples of index.", indices.len());

    let digest_file = File::open(args.digest_file).expect("Could not open partial digest file");
    let mut partial_digest = vec![];
    let mut digest_line = String::new();
    BufReader::new(digest_file)
        .read_line(&mut digest_line)
        .expect("Could not read a line from partial digest file");
    partial_digest.extend(
        digest_line
            .trim()
            .split(" ")
            .map(|x| x.parse::<u8>().expect("Could not parse a digest byte")),
    );

    let started_on = OffsetDateTime::now_utc();
    async_writeln!(
        output_file,
        "Started on: {}",
        started_on.format(&Iso8601::DEFAULT).unwrap()
    )?;

    let mut hash_count: i64 = 0;
    let mut end = false;
    for tuple in indices {
        for perm in tuple.into_iter().permutations(12) {
            hash_count += 1;
            if hash_count == args.max_tries + 1 {
                println!("end");
                end = true;
                break;
            }
            let mut hasher = Sha256::new();
            let bytearray = perm_to_bytearray(&perm);
            hasher.update(bytearray);
            let digest = hasher.finalize();
            if (digest[0] >> 4) != low_nbits(perm[11], 4) as u8 {
                continue;
            }

            let sentence = perm.into_iter().map(|x| dictionary[&x].clone()).join(" ");
            let mut derived_key: Vec<u8> = vec![];
            pbkdf2::<Hmac<Sha512>>(
                sentence.as_bytes(),
                "mnemonic".as_bytes(),
                2048,
                derived_key.as_mut(),
            );
            let mut mac = Hmac::<Sha512>::new_from_slice(b"Bitcoin seed").unwrap();
            mac.update(derived_key.as_ref());
            let code = mac.finalize().into_bytes();
            if code[32..] == partial_digest[..] {
                async_writeln!(output_file, "{}", sentence)?;
            }
        }
        if end {
            break;
        }
    }

    let finished_on = OffsetDateTime::now_utc();
    async_writeln!(
        output_file,
        "Finished on: {}",
        finished_on.format(&Iso8601::DEFAULT).unwrap()
    )?;
    let elapsed = finished_on - started_on;
    async_writeln!(
        output_file,
        "Hashrate: {} hashes/sec",
        hash_count as f64 / elapsed.as_seconds_f64()
    )?;
    Ok(())
}

#[test]
fn test_high_nbits() {
    assert_eq!(high_nbits(0b101010, 3, 6), 0b101);
    assert_eq!(high_nbits(0b00101010, 3, 8), 0b001);
}

#[test]
fn test_low_nbits() {
    assert_eq!(low_nbits(0b101010, 3), 0b010);
}
