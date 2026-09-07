// SPDX-License-Identifier: Apache-2.0

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
mod ticket;

use clap::{Command, CommandFactory, Parser};
use log::error;
use std::process::ExitCode;

/// Build the command-line interface definition.
pub fn command() -> Command {
    cli::Cli::command()
}

/// Parse the command line and execute the selected TPM command.
pub fn run() -> ExitCode {
    let cli = cli::Cli::parse();

    if let Err(e) = logger::init_logger(cli.global.verbosity, cli.global.log_file.clone()) {
        eprintln!("error: failed to initialise logger: {e}");
        return ExitCode::FAILURE;
    }

    if let Err(e) = cli.command.execute(&cli.global) {
        error!("{e:#}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
