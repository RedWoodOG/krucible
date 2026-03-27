use colored::Colorize;
use super::schema::{AuditReport, Severity};

pub fn print_human(report: &AuditReport) {
    println!("{}", "═══════════════════════════════════════".dimmed());
    println!("{}", "  KRUCIBLE AUDIT REPORT".bold());
    println!("{}", "═══════════════════════════════════════".dimmed());
    println!("  Repo:          {}", report.repo);
    println!("  Files scanned: {}", report.files_scanned);
    println!("  Issues found:  {}", report.issues.len());
    println!("  {} HIGH  {} MEDIUM", 
        report.high_count().to_string().red().bold(),
        report.medium_count().to_string().yellow().bold()
    );
    println!("{}", "═══════════════════════════════════════".dimmed());
    println!();

    if report.issues.is_empty() {
        println!("{}", "  ✓ No issues found.".green().bold());
        return;
    }

    for issue in &report.issues {
        let severity_label = match issue.severity {
            Severity::High => format!("[{}]", issue.severity).red().bold().to_string(),
            Severity::Medium => format!("[{}]", issue.severity).yellow().bold().to_string(),
            Severity::Low => format!("[{}]", issue.severity).blue().to_string(),
            Severity::Info => format!("[{}]", issue.severity).dimmed().to_string(),
        };

        print!("{} ", severity_label);
        println!("{}", issue.message.bold());
        println!("    File: {}{}", issue.file, 
            issue.line.map(|l| format!(":{l}")).unwrap_or_default()
        );

        if let (Some(claim), Some(reality)) = (&issue.claim, &issue.reality) {
            println!("    {}: {}", "CLAIM".cyan(), claim);
            println!("    {}: {}", "REALITY".red(), reality);
        }

        println!();
    }
}

pub fn print_json(report: &AuditReport) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(report)?);
    Ok(())
}
