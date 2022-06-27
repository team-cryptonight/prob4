use std::io::{self, Write};

use clap::Parser;
use time::{format_description::well_known::Iso8601, OffsetDateTime};
use tokio::{fs::File, io::AsyncWriteExt};

macro_rules! async_writeln {
    ($dst: expr) => {
        {
            AsyncWriteExt::write_all(&mut $dst, b"\n").await
        }
    };
    ($dst: expr, $fmt: expr) => {
        {
            use std::io::Write;
            let mut buf = Vec::<u8>::new();
            writeln!(buf, $fmt)?;
            AsyncWriteExt::write_all(&mut $dst, &buf).await
        }
    };
    ($dst: expr, $fmt: expr, $($arg: tt)*) => {
        {
            use std::io::Write;
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

    /// Path to output file
    #[clap(short, long, value_parser, default_value = "result.txt")]
    output_file: String,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();
    let mut output_file = File::create(args.output_file).await?;
    let started_on = OffsetDateTime::now_utc();
    async_writeln!(
        output_file,
        "Started on: {}",
        started_on.format(&Iso8601::DEFAULT).unwrap()
    )?;
    let finished_on = OffsetDateTime::now_utc();
    async_writeln!(
        output_file,
        "Finished on: {}",
        finished_on.format(&Iso8601::DEFAULT).unwrap()
    )?;
    Ok(())
}
