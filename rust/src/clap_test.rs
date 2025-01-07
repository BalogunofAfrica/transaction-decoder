
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "Bitcoin CLI")]
#[command(version = "1.0")]
#[command(about = "Bitcoin Core RPC Client", long_about=None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>
}

#[derive(Subcommand)]
enum Commands {
    // Returns a hash of block in best block-chain at height provided.
    Getblockhash {
        #[arg(
            required = true,
            help = "(numeric, required) The height index"
        )]
        height: u64
    }
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Getblockhash { height }) => {
            println!("Returns the block height for {}", height)
        },
        None => {
            eprintln!("Too few arguments");
        }
    }
}