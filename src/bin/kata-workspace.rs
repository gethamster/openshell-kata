//! Guest-side System workspace operations without an interpreter dependency.

use anyhow::Result;
use clap::{Parser, Subcommand};
use openshell_kata::workspace::{self, RemoveOptions, Workspace};
use std::{path::PathBuf, process::ExitCode};

#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    /// Trusted workspace root override for isolated integration fixtures.
    #[arg(long, default_value = "/sandbox")]
    root: PathBuf,
    #[command(subcommand)]
    command: Operation,
}

#[derive(Debug, Subcommand)]
enum Operation {
    Protocol,
    Run {
        id: String,
        command_json: String,
    },
    Kill {
        id: String,
    },
    Read {
        path: String,
    },
    Write {
        path: String,
    },
    Remove {
        path: String,
        #[arg(action = clap::ArgAction::Set)]
        recursive: bool,
        #[arg(action = clap::ArgAction::Set)]
        force: bool,
    },
    #[command(name = "__run-child", hide = true)]
    RunChild {
        id: String,
        command_json: String,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    match execute(Cli::parse()).await {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(error) => {
            eprintln!("kata-workspace: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn execute(cli: Cli) -> Result<i32> {
    if matches!(cli.command, Operation::Protocol) {
        println!("openshell-kata-workspace/1");
        return Ok(0);
    }
    let workspace = Workspace::open(cli.root)?;
    match cli.command {
        Operation::Protocol => unreachable!("protocol was handled before opening a workspace"),
        Operation::Run { id, command_json } => workspace::run(&workspace, &id, &command_json).await,
        Operation::RunChild { id, command_json } => {
            workspace::run_child(&workspace, &id, &command_json).await
        }
        Operation::Kill { id } => {
            workspace::kill(&workspace, &id)?;
            Ok(0)
        }
        Operation::Read { path } => Ok(if workspace.read(&path, std::io::stdout().lock())? {
            0
        } else {
            66
        }),
        Operation::Write { path } => {
            workspace.write(&path, std::io::stdin().lock())?;
            Ok(0)
        }
        Operation::Remove {
            path,
            recursive,
            force,
        } => {
            workspace.remove(&path, RemoveOptions { recursive, force })?;
            Ok(0)
        }
    }
}
