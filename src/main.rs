mod cli;
mod cmd;
mod context;
mod error;
mod handle;
mod logger;
mod output;
mod parse;
mod pcr;
mod raw_esys;
mod session;
mod tcti;

use clap::Parser;
use log::error;

fn main() {
    let cli = cli::Cli::parse();

    if let Err(e) = logger::init_logger(cli.global.verbosity, cli.global.log_file.clone()) {
        eprintln!("error: failed to initialise logger: {e}");
        std::process::exit(1);
    }

    if let Err(e) = cli.command.execute(&cli.global) {
        error!("{e:#}");
        std::process::exit(1);
    }
}
