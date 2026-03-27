use clap::{Parser, ValueEnum};
use std::path::PathBuf;
use krucible::engine::audit_engine::{self, AuditOptions};
use krucible::report::formatter;

#[derive(Parser)]
#[command(
    name = "krucible",
    version = "0.1.0",
    about = "Structural code verification — is this code real, or just glue?",
    long_about = "Krucible audits repositories for dead code, fake wiring, AI slop, \
                  and contract violations. Use --deep to enable LLM-powered analysis \
                  via a local Qwen2.5-32B model (requires LiteLLM proxy on localhost:4000)."
)]
struct Cli {
    /// Path to the repository to audit
    #[arg(value_name = "REPO_PATH")]
    path: PathBuf,

    /// Output format
    #[arg(short, long, value_enum, default_value = "human")]
    format: OutputFormat,

    /// Write report to file (JSON)
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Enable LLM-powered deep analysis (requires LiteLLM proxy on localhost:4000)
    #[arg(long, default_value_t = false)]
    deep: bool,
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if !cli.path.exists() {
        eprintln!("Error: path '{}' does not exist.", cli.path.display());
        std::process::exit(2);
    }

    let opts = AuditOptions { deep: cli.deep };
    let report = audit_engine::run_audit(&cli.path, opts)?;

    match cli.format {
        OutputFormat::Human => formatter::print_human(&report),
        OutputFormat::Json => formatter::print_json(&report)?,
    }

    if let Some(out_path) = cli.output {
        let json = serde_json::to_string_pretty(&report)?;
        std::fs::write(&out_path, json)?;
        eprintln!("Report written to {}", out_path.display());
    }

    // Exit 1 if HIGH issues found (CI-friendly)
    if report.high_count() > 0 {
        std::process::exit(1);
    }

    Ok(())
}
