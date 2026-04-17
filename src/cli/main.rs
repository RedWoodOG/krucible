use clap::{Parser, ValueEnum};
use std::collections::HashSet;
use std::path::PathBuf;
use krucible::engine::audit_engine::{self, AuditOptions};
use krucible::report::formatter;
use krucible::report::schema::BaselineSnapshot;

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

    /// Write report to file (JSON or SARIF)
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Baseline report path (JSON or SARIF) for diffing current findings
    #[arg(long, value_name = "FILE")]
    baseline: Option<PathBuf>,

    /// Show only findings not present in baseline
    #[arg(long, default_value_t = false)]
    only_new: bool,

    /// Write current findings as a baseline snapshot
    #[arg(long, value_name = "FILE")]
    write_baseline: Option<PathBuf>,

    /// Enable LLM-powered deep analysis (requires LiteLLM proxy on localhost:4000)
    #[arg(long, default_value_t = false)]
    deep: bool,

    /// Optional flow model file (JSON) overriding default source/sink/guard profiles
    #[arg(long, value_name = "FILE")]
    flow_model: Option<PathBuf>,

    /// Do not run cargo check / npx tsc for compiler diagnostics
    #[arg(long, default_value_t = false)]
    skip_compiler_diagnostics: bool,

    /// Maximum allowed HIGH findings before non-zero exit
    #[arg(long, value_name = "N")]
    max_high: Option<usize>,

    /// Maximum allowed MEDIUM findings before non-zero exit
    #[arg(long, value_name = "N")]
    max_medium: Option<usize>,

    /// Maximum allowed LOW findings before non-zero exit
    #[arg(long, value_name = "N")]
    max_low: Option<usize>,
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
    Sarif,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if !cli.path.exists() {
        eprintln!("Error: path '{}' does not exist.", cli.path.display());
        std::process::exit(2);
    }

    let opts = AuditOptions {
        deep: cli.deep,
        flow_model_path: cli.flow_model.clone(),
        skip_compiler_diagnostics: cli.skip_compiler_diagnostics,
    };
    if let Some(path) = &cli.flow_model {
        if !path.exists() {
            anyhow::bail!("Flow model path '{}' does not exist.", path.display());
        }
    }
    let mut report = audit_engine::run_audit(&cli.path, opts)?;
    let full_report = report.clone();

    if let Some(path) = &cli.baseline {
        let baseline_fingerprints = load_baseline_fingerprints(path)?;
        if cli.only_new {
            report.issues.retain(|issue| !baseline_fingerprints.contains(&issue.fingerprint()));
        }
    }

    match cli.format {
        OutputFormat::Human => formatter::print_human(&report),
        OutputFormat::Json => formatter::print_json(&report)?,
        OutputFormat::Sarif => formatter::print_sarif(&report)?,
    }

    if let Some(out_path) = &cli.output {
        let payload = match cli.format {
            OutputFormat::Sarif => serde_json::to_string_pretty(&report.to_sarif())?,
            _ => serde_json::to_string_pretty(&report.to_json_report())?,
        };
        std::fs::write(out_path, payload)?;
        eprintln!("Report written to {}", out_path.display());
    }

    if let Some(path) = &cli.write_baseline {
        let baseline = full_report.to_baseline_snapshot();
        let payload = serde_json::to_string_pretty(&baseline)?;
        std::fs::write(path, payload)?;
        eprintln!("Baseline written to {}", path.display());
    }

    // CI policy:
    // - If explicit max thresholds are set, enforce those.
    // - Otherwise preserve default behavior: fail on any HIGH issue.
    if violates_policy(&report, &cli) {
        std::process::exit(1);
    }

    Ok(())
}

fn violates_policy(report: &krucible::report::schema::AuditReport, cli: &Cli) -> bool {
    if let Some(max_high) = cli.max_high {
        if report.high_count() > max_high {
            return true;
        }
    }
    if let Some(max_medium) = cli.max_medium {
        if report.medium_count() > max_medium {
            return true;
        }
    }
    if let Some(max_low) = cli.max_low {
        if report.low_count() > max_low {
            return true;
        }
    }

    // Preserve current default behavior if no policy flags are provided.
    if cli.max_high.is_none() && cli.max_medium.is_none() && cli.max_low.is_none() {
        return report.high_count() > 0;
    }

    false
}

fn load_baseline_fingerprints(path: &std::path::Path) -> anyhow::Result<HashSet<String>> {
    let raw = std::fs::read_to_string(path)?;
    let parsed: serde_json::Value = serde_json::from_str(&raw)?;
    let mut out = HashSet::new();
    let mut recognized = false;

    // Baseline snapshot format: { "fingerprints": [...] }
    if let Ok(snapshot) = serde_json::from_value::<BaselineSnapshot>(parsed.clone()) {
        out.extend(snapshot.fingerprints);
        return Ok(out);
    }

    // Krucible JSON format: { "issues": [{ "fingerprint": ... }, ...] }
    if let Some(issues) = parsed.get("issues").and_then(|v| v.as_array()) {
        recognized = true;
        for issue in issues {
            if let Some(fp) = issue.get("fingerprint").and_then(|v| v.as_str()) {
                out.insert(fp.to_string());
            }
        }
    }

    // SARIF: partialFingerprints.primaryLocationLineHash (or legacy snake_case)
    if let Some(runs) = parsed.get("runs").and_then(|v| v.as_array()) {
        recognized = true;
        for run in runs {
            if let Some(results) = run.get("results").and_then(|v| v.as_array()) {
                for result in results {
                    if let Some(fp) = sarif_partial_fingerprint(result) {
                        out.insert(fp.to_string());
                    }
                }
            }
        }
    }

    if !recognized {
        anyhow::bail!(
            "Unsupported baseline format in '{}'. Expected Krucible baseline/JSON report or SARIF.",
            path.display()
        );
    }

    Ok(out)
}

fn sarif_partial_fingerprint(result: &serde_json::Value) -> Option<&str> {
    let pf = result
        .get("partialFingerprints")
        .or_else(|| result.get("partial_fingerprints"))?;
    pf.get("primaryLocationLineHash")
        .or_else(|| pf.get("primary_location_line_hash"))
        .and_then(|v| v.as_str())
}
