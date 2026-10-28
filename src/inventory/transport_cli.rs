//! Explicit transport modes preserve the original file-generator CLI.
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Transport one configured inventory authority through an exact API object.
#[derive(Debug, Parser)]
#[command(name = "kata-network-inventory")]
pub struct TransportCli {
    #[command(subcommand)]
    action: Action,
}
#[derive(Debug, Subcommand)]
enum Action {
    Publish {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        once: bool,
    },
    Courier {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        once: bool,
    },
}
/// Run the selected bounded publisher or read-only courier.
pub async fn run_transport(cli: TransportCli) -> Result<()> {
    match cli.action {
        Action::Publish { config, once } => super::transport::run_publisher(&config, once).await,
        Action::Courier { config, once } => super::transport::run_courier(&config, once).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_requires_an_explicit_known_mode_and_configuration() {
        for mode in ["publish", "courier"] {
            assert!(
                TransportCli::try_parse_from([
                    "inventory",
                    mode,
                    "--config",
                    "/operator.json",
                    "--once"
                ])
                .is_ok()
            );
            assert!(TransportCli::try_parse_from(["inventory", mode]).is_err());
        }
        assert!(
            TransportCli::try_parse_from(["inventory", "delete", "--config", "/operator.json"])
                .is_err()
        );
    }
}
