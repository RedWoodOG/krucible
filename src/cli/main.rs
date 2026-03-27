use clap::{Parser, ValueEnum};
use std::path::PathBuf;
use krucible::engine::audit_engine;
use krucible::report::formatter;

#[derive(Parser)]
#[command(
    name = "krucible",
    version = "0.1.0",
    about = "Structural code verification — is this code real, or just glue?",
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

    let report = audit_engine::run_audit(&cli.path)?;

    match cli.format {
        OutputFormat::Human => formatter::print_human(&report),
        OutputFormat::Json => formatter::print_json(&report)?,
    }

    if let Some(out_path) = cli.output {
        let json = serde_json::to_string_pretty(&report)?;
        std::fs::write(&out_path, json)?;
        eprintln!("Report written to {}", out_path.display());
    }

    // Exit 1 if HIGH issues found
    if report.high_count() > 0 {
        std::process::exit(1);
    }

    Ok(())
}
