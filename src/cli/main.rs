use clap::{Parser, ValueEnum};
use std::path::PathBuf;

use krucible::scanner;
use krucible::report;

#[derive(Parser)]
#[command(
    name = "krucible",
    version = "0.1.0",
    about = "Structural code verification — is this code real, or just glue?",
    long_about = None
)]
struct Cli {
    /// Path to the repository to audit
    #[arg(value_name = "REPO_PATH")]
    path: PathBuf,

    /// Output format
    #[arg(short, long, value_enum, default_value = "human")]
    format: OutputFormat,

    /// Write JSON report to file
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    println!("Krucible Audit v0.1.0");
    println!("Scanning: {}", cli.path.display());
    println!();

    let files = scanner::file_loader::load_files(&cli.path)?;
    println!("Found {} files to analyze", files.len());

    for f in &files {
        println!("  {} [{}]", f.path.display(), f.language);
    }

    Ok(())
}
