//! Trusted hosted startup operations without a Python interpreter dependency.

use anyhow::Result;
use clap::{Parser, Subcommand};
use openshell_kata::operator::{self, Prepare};
use std::{path::PathBuf, process::ExitCode};

#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    operation: Operation,
}

#[derive(Debug, Subcommand)]
enum Operation {
    SocketReady {
        #[arg(long)]
        socket: PathBuf,
    },
    Prepare {
        #[arg(long)]
        state_dir: Option<PathBuf>,
        #[arg(long)]
        driver_dir: Option<PathBuf>,
        #[arg(long)]
        registry_dir: PathBuf,
        #[arg(long)]
        system_ca: PathBuf,
        #[arg(long)]
        platform_ca: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    match execute(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("kata-operator: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn execute(cli: Cli) -> Result<()> {
    match cli.operation {
        Operation::SocketReady { socket } => operator::socket_ready(&socket).await,
        Operation::Prepare {
            state_dir,
            driver_dir,
            registry_dir,
            system_ca,
            platform_ca,
            output,
        } => operator::prepare(&Prepare {
            state_dir,
            driver_dir,
            registry_dir,
            system_ca,
            platform_ca,
            output,
        }),
    }
}
