use anyhow::Result;
use std::path::Path;
use crate::scanner::file_loader;
use crate::parser::tree_sitter as ts_parser;
use crate::analyzers::{wiring, slop};
use crate::report::schema::AuditReport;

pub fn run_audit(repo_path: &Path) -> Result<AuditReport> {
    let repo_str = repo_path.display().to_string();

    // Phase 1: Load files
    let source_files = file_loader::load_files(repo_path)?;

    // Phase 2: Parse
    let parsed: Vec<_> = source_files.iter()
        .filter_map(|f| ts_parser::parse_file(f).ok())
        .collect();

    // Phase 3: Analyze
    let mut report = AuditReport::new(&repo_str, source_files.len());

    // Wiring check
    let mut wiring_issues = wiring::analyze(&parsed);
    report.issues.append(&mut wiring_issues);

    // Slop check
    let mut slop_issues = slop::analyze(&source_files);
    report.issues.append(&mut slop_issues);

    // Sort: HIGH first
    report.issues.sort_by(|a, b| {
        use crate::report::schema::Severity::*;
        let rank = |s: &crate::report::schema::Severity| match s {
            High => 0,
            Medium => 1,
            Low => 2,
            Info => 3,
        };
        rank(&a.severity).cmp(&rank(&b.severity))
    });

    Ok(report)
}
