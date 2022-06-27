use clap::Parser;

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

fn main() {
    let args = Args::parse();
    println!("{:?}", args);
}
