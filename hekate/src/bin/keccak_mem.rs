use clap::Parser;
use hekate::{prepare_keccak, prove_keccak};

#[derive(Parser, Debug)]
struct Args {
    /// Input size in bytes for the Keccak benchmark
    #[arg(long = "input-size")]
    input_size: usize,
}

fn main() {
    let args = Args::parse();

    let prepared = prepare_keccak(args.input_size);
    prove_keccak(&prepared);
}
