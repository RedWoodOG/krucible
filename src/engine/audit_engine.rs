use anyhow::Result;
use std::path::Path;
use crate::scanner::file_loader;
use crate::parser::tree_sitter as ts_parser;
use crate::analyzers::{wiring, slop, contracts, execution};
use crate::report::schema::AuditReport;

pub fn run_audit(repo_path: &Path) -> Result<AuditReport> {
    let repo_str = repo_path.display().to_string();

    // Phase 1: Load files
    let source_files = file_loader::load_files(repo_path)?;
    let file_count = source_files.len();

    if file_count == 0 {
        eprintln!("No supported source files found (.ts, .tsx, .js, .rs)");
        return Ok(AuditReport::new(&repo_str, 0));
    }

    // Phase 2: Parse
    let parsed: Vec<_> = source_files.iter()
        .filter_map(|f| ts_parser::parse_file(f).ok())
        .collect();

    // Phase 3: Analyze — all four analyzers
    let mut report = AuditReport::new(&repo_str, file_count);

    // 1. Wiring: dead code, unused functions
    let mut wiring_issues = wiring::analyze(&parsed);
    report.issues.append(&mut wiring_issues);

    // 2. Slop: TODOs, mocks, stubs, temp fixes
    let mut slop_issues = slop::analyze(&source_files);
    report.issues.append(&mut slop_issues);

    // 3. Contracts: Reality Gap — name implies X but code does Y
    let mut contract_issues = contracts::analyze(&parsed);
    report.issues.append(&mut contract_issues);

    // 4. Empty action stubs
    let mut stub_issues = contracts::analyze_empty_stubs(&parsed);
    report.issues.append(&mut stub_issues);

    // 5. Execution integrity: async without await, unhandled promises
    let mut exec_issues = execution::analyze(&source_files);
    report.issues.append(&mut exec_issues);

    // Sort: HIGH → MEDIUM → LOW → INFO
    report.issues.sort_by_key(|i| {
        use crate::report::schema::Severity::*;
        match i.severity {
            High => 0,
            Medium => 1,
            Low => 2,
            Info => 3,
        }
    });

    // Deduplicate: same file + line + message
    report.issues.dedup_by(|a, b| {
        a.file == b.file && a.line == b.line && a.message == b.message
    });

    Ok(report)
}
