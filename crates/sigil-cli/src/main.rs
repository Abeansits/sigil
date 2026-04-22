#![allow(clippy::print_stdout, clippy::print_stderr)]

use anyhow::Result;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    // Write tracing output to stderr so `--json` stdout stays pure for `| jq`
    // pipelines. Without this, the `loaded audit HMAC key` / migration INFO
    // lines leak into JSON output and break downstream parsers.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = sigil_cli::Cli::parse();
    Box::pin(sigil_cli::run(cli)).await
}
