use std::{
    collections::HashMap,
    fs::File,
    io::{self, stdout, BufRead, BufReader, Write},
    sync::mpsc::{self, Sender},
    thread,
};

use bip39_utils::bip39_utils::{indices_to_sentence, mnemonic_to_seed, sentence_checksum};
use bit_utils::bit_utils::{low_nbits, perm_to_bytearray};
use clap::Parser;
use crossterm::{cursor, ExecutableCommand};
use hmac::{Hmac, Mac};
use itertools::Itertools;
use sha2::Sha512;
use time::{format_description::well_known::Iso8601, OffsetDateTime};
use tokio::{fs::File as TokioFile, io::AsyncWriteExt};

pub mod bip39_utils;
pub mod bit_utils;

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

    /// Maximum tries count (all permutations are tried if set to -1)
    #[clap(long, value_parser, default_value_t = -1)]
    max_tries: i64,

    /// Show progress
    #[clap(short, long, action)]
    verbose: bool,
}

#[derive(Debug)]
enum ThreadStatus {
    Trying(String),
    Matched(String),
    Finished(i64),
}

fn crack_loop(
    dictionary: HashMap<u32, String>,
    indices: Vec<Vec<u32>>,
    partial_digest: Vec<u8>,
    thread_id: u32,
    tx: Sender<(u32, ThreadStatus)>,
    verbose_output: bool,
    max_tries: i64,
) {
    let mut hash_count: i64 = 0;
    let mut end = false;
    for tuple in indices {
        for perm in tuple.into_iter().permutations(12) {
            hash_count += 1;
            if hash_count == max_tries + 1 {
                end = true;
                break;
            }

            let perm_arr: [u32; 12] = perm.try_into().unwrap();
            let bytearray = perm_to_bytearray(&perm_arr);
            if sentence_checksum(&bytearray) != low_nbits(perm_arr[11], 4) as u8 {
                continue;
            }
            let sentence = indices_to_sentence(&perm_arr, &dictionary);
            if verbose_output {
                tx.send((thread_id, ThreadStatus::Trying(sentence.clone())))
                    .unwrap();
            }
            let derived_key = mnemonic_to_seed(sentence.as_str());
            let mut mac = Hmac::<Sha512>::new_from_slice(b"Bitcoin seed").unwrap();
            mac.update(derived_key.as_ref());
            let code = mac.finalize().into_bytes();
            if code[32..] == partial_digest[..] {
                tx.send((thread_id, ThreadStatus::Matched(sentence)))
                    .unwrap();
            }
        }
        if end {
            break;
        }
    }
    tx.send((thread_id, ThreadStatus::Finished(hash_count)))
        .unwrap();
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

    let spawned_thread_count = args.thread_count.clamp(1, indices.len() as u32);
    let (tx, rx) = mpsc::channel();
    println!("Spawning {} threads...", spawned_thread_count);
    for thread_id in 0..spawned_thread_count {
        let dictionary_cloned = dictionary.clone();
        let indices_cloned = indices[thread_id as usize..]
            .into_iter()
            .step_by(spawned_thread_count as usize)
            .map(|v| v.clone())
            .collect::<Vec<_>>();
        let partial_digest_cloned = partial_digest.clone();
        let tx_cloned = tx.clone();

        thread::spawn(move || {
            crack_loop(
                dictionary_cloned,
                indices_cloned,
                partial_digest_cloned,
                thread_id,
                tx_cloned,
                args.verbose,
                args.max_tries,
            );
        });
    }

    let mut hash_count = 0;
    let mut finished_threads = 0;
    for _ in 1..spawned_thread_count {
        println!();
    }
    stdout()
        .execute(cursor::MoveToPreviousLine(spawned_thread_count as u16 - 1))
        .unwrap()
        .execute(cursor::SavePosition)
        .unwrap();
    stdout().flush().unwrap();
    for received in rx {
        match received.1 {
            ThreadStatus::Trying(x) => {
                stdout()
                    .execute(cursor::MoveToNextLine(received.0 as u16))
                    .unwrap();
                print!("[Thread {}] Trying: {}", received.0, x);
                stdout().execute(cursor::RestorePosition).unwrap();
            }
            ThreadStatus::Matched(x) => {
                stdout()
                    .execute(cursor::MoveToNextLine(received.0 as u16))
                    .unwrap();
                print!("[Thread {}] Matched: {}", received.0, x);
                async_writeln!(output_file, "Match: {}", x)?;
                stdout().execute(cursor::RestorePosition).unwrap();
            }
            ThreadStatus::Finished(x) => {
                stdout()
                    .execute(cursor::MoveToNextLine(received.0 as u16))
                    .unwrap();
                print!("[Thread {}] Finished!", received.0);
                stdout().execute(cursor::RestorePosition).unwrap();
                hash_count += x;
                finished_threads += 1;
                if finished_threads == spawned_thread_count {
                    if args.verbose {
                        stdout()
                            .execute(cursor::MoveToNextLine(spawned_thread_count as u16))
                            .unwrap();
                    }
                    break;
                }
            }
        }
        stdout().flush().unwrap();
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
