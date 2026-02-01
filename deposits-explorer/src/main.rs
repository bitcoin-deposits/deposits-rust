use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

mod app;
mod api;
mod deposits;
mod ui;
mod util;

#[derive(Parser, Debug)]
#[command(name = "deposits-explorer")]
#[command(about = "Terminal-based Bitcoin + Deposits protocol explorer")]
pub struct Args {
    /// Electrs REST API URL
    #[arg(long, env = "ELECTRS_URL", default_value = "http://localhost:3102")]
    pub electrs: String,

    /// Deposits data directory (contains ledgers.json)
    #[arg(long, env = "DEPOSITS_DATA_DIR")]
    pub data_dir: Option<PathBuf>,

    /// Refresh interval in seconds (0 to disable auto-refresh)
    #[arg(long, default_value = "5")]
    pub refresh: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Resolve data directory
    let data_dir = args.data_dir.unwrap_or_else(|| {
        // Check for /data first (container), then ~/.deposits-bdk
        let container_path = PathBuf::from("/data");
        if container_path.exists() {
            container_path
        } else {
            dirs::home_dir()
                .map(|h| h.join(".deposits-bdk"))
                .unwrap_or_else(|| PathBuf::from(".deposits-bdk"))
        }
    });

    app::run(args.electrs, data_dir, args.refresh).await
}
