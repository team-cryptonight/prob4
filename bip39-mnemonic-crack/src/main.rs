use std::io::{self, Write};

use clap::Parser;
use time::{format_description::well_known::Iso8601, OffsetDateTime};
use tokio::{fs::File, io::AsyncWriteExt};

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
    {
        let mut buf = Vec::<u8>::new();
        let start_msg = format!(
            "Started on: {}",
            started_on.format(&Iso8601::DEFAULT).unwrap()
        );
        println!("{}", start_msg);
        writeln!(buf, "{}", start_msg)?;
        AsyncWriteExt::write_all(&mut output_file, &buf).await?;
    }
    let finished_on = OffsetDateTime::now_utc();
    {
        let mut buf = Vec::<u8>::new();
        let finish_msg = format!(
            "Finished on: {}",
            finished_on.format(&Iso8601::DEFAULT).unwrap()
        );
        println!("{}", finish_msg);
        writeln!(buf, "{}", finish_msg)?;
        AsyncWriteExt::write_all(&mut output_file, &buf).await?;
    }
    Ok(())
}
