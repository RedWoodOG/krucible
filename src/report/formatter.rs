use colored::Colorize;
use super::schema::{AuditReport, Severity, IssueType};

pub fn print_human(report: &AuditReport) {
    println!("{}", "═══════════════════════════════════════════════════".dimmed());
    println!("{}", "  KRUCIBLE AUDIT REPORT".bold().white());
    println!("{}", "═══════════════════════════════════════════════════".dimmed());
    println!("  Repo:          {}", report.repo.cyan());
    println!("  Files scanned: {}", report.files_scanned);
    println!("  Issues found:  {}", report.issues.len());
    println!(
        "  {} HIGH   {} MEDIUM   {} LOW",
        report.high_count().to_string().red().bold(),
        report.medium_count().to_string().yellow().bold(),
        report.low_count().to_string().blue()
    );
    println!("{}", "═══════════════════════════════════════════════════".dimmed());
    println!();

    if report.issues.is_empty() {
        println!("{}", "  ✓ No issues found. Code looks real.".green().bold());
        return;
    }

    // Group by type for cleaner output
    let reality_gaps: Vec<_> = report.issues.iter()
        .filter(|i| matches!(i.issue_type, IssueType::ContractViolation | IssueType::FakeWiring))
        .collect();

    let dead_code: Vec<_> = report.issues.iter()
        .filter(|i| matches!(i.issue_type, IssueType::DeadCode))
        .collect();

    let slop: Vec<_> = report.issues.iter()
        .filter(|i| matches!(i.issue_type, IssueType::AiSlop))
        .collect();

    let exec: Vec<_> = report.issues.iter()
        .filter(|i| matches!(i.issue_type, IssueType::UnresolvedAsync))
        .collect();

    // Reality Gap section — the killer feature
    if !reality_gaps.is_empty() {
        println!("{}", "  ◆ REALITY GAP".red().bold());
        println!("{}", "  ─────────────────────────────────────────────────".dimmed());
        for issue in &reality_gaps {
            print_issue(issue);
        }
    }

    if !dead_code.is_empty() {
        println!("{}", "  ◆ DEAD CODE / FAKE WIRING".yellow().bold());
        println!("{}", "  ─────────────────────────────────────────────────".dimmed());
        for issue in &dead_code {
            print_issue(issue);
        }
    }

    if !exec.is_empty() {
        println!("{}", "  ◆ EXECUTION PATH ISSUES".yellow().bold());
        println!("{}", "  ─────────────────────────────────────────────────".dimmed());
        for issue in &exec {
            print_issue(issue);
        }
    }

    if !slop.is_empty() {
        println!("{}", "  ◆ AI SLOP DETECTED".yellow().bold());
        println!("{}", "  ─────────────────────────────────────────────────".dimmed());
        for issue in &slop {
            print_issue(issue);
        }
    }

    // Summary verdict
    println!("{}", "═══════════════════════════════════════════════════".dimmed());
    if report.high_count() > 0 {
        println!("{}", "  ✗ VERDICT: Code has critical structural issues.".red().bold());
    } else if report.medium_count() > 0 {
        println!("{}", "  ⚠ VERDICT: Code has wiring issues. Review before shipping.".yellow().bold());
    } else {
        println!("{}", "  ✓ VERDICT: No critical issues found.".green().bold());
    }
    println!("{}", "═══════════════════════════════════════════════════".dimmed());
}

fn print_issue(issue: &super::schema::Issue) {
    let severity_label = match issue.severity {
        Severity::High   => "[HIGH]  ".red().bold().to_string(),
        Severity::Medium => "[MED]   ".yellow().bold().to_string(),
        Severity::Low    => "[LOW]   ".blue().to_string(),
        Severity::Info   => "[INFO]  ".dimmed().to_string(),
    };

    println!("  {} {}", severity_label, issue.message.bold());
    println!("           {} {}{}",
        "→".dimmed(),
        issue.file.dimmed(),
        issue.line.map(|l| format!(":{l}")).unwrap_or_default().dimmed()
    );

    if let (Some(claim), Some(reality)) = (&issue.claim, &issue.reality) {
        println!("           {} {}", "CLAIM:  ".cyan(), claim);
        println!("           {} {}", "REALITY:".red(), reality);
    }

    println!();
}

pub fn print_json(report: &AuditReport) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(report)?);
    Ok(())
}
