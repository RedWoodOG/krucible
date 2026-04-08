use anyhow::Result;
use std::path::Path;
use std::collections::HashMap;
use crate::scanner::file_loader;
use crate::parser::tree_sitter as ts_parser;
use crate::analyzers::{wiring, slop, contracts, execution, llm, tauri};
use crate::report::schema::AuditReport;

#[derive(Default)]
pub struct AuditOptions {
    /// Enable LLM-powered deep analysis (requires LiteLLM proxy on localhost:4000)
    pub deep: bool,
}

pub fn run_audit(repo_path: &Path, opts: AuditOptions) -> Result<AuditReport> {
    let repo_str = repo_path.display().to_string();

    // Phase 1: Load files
    let source_files = file_loader::load_files(repo_path)?;
    let file_count = source_files.len();

    if file_count == 0 {
        eprintln!("No supported source files found (.ts, .tsx, .js, .rs)");
        return Ok(AuditReport::new(&repo_str, 0));
    }

    // Build source map for LLM analyzer (file path → raw content)
    let source_map: HashMap<String, String> = source_files
        .iter()
        .map(|f| (f.path.display().to_string(), f.content.clone()))
        .collect();

    // Phase 2: Parse
    let parsed: Vec<_> = source_files.iter()
        .filter_map(|f| ts_parser::parse_file(f).ok())
        .collect();

    let mut report = AuditReport::new(&repo_str, file_count);

    // --- Static analyzers (always run) ---

    // 1. Wiring: dead code, unused functions
    let mut wiring_issues = wiring::analyze(&parsed);
    report.issues.append(&mut wiring_issues);

    // 2. Slop: TODOs, mocks, stubs, temp fixes
    let mut slop_issues = slop::analyze(&source_files);
    report.issues.append(&mut slop_issues);

    // 3. Contracts: heuristic Reality Gap
    let mut contract_issues = contracts::analyze(&parsed);
    report.issues.append(&mut contract_issues);

    // 4. Empty action stubs
    let mut stub_issues = contracts::analyze_empty_stubs(&parsed);
    report.issues.append(&mut stub_issues);

    // 5. Execution integrity: async without await, unhandled promises
    let mut exec_issues = execution::analyze(&source_files);
    report.issues.append(&mut exec_issues);

    // 6. Tauri command wiring: annotation vs registration vs frontend invocation
    let mut tauri_issues = tauri::analyze(&parsed, &source_map);
    report.issues.append(&mut tauri_issues);

    // --- LLM-powered deep analysis (--deep flag) ---
    if opts.deep {
        eprintln!("\nRunning deep LLM analysis via Qwen2.5-32B...");
        eprintln!("(This makes one LLM call per action function — may take a minute)\n");

        let mut llm_issues = llm::analyze(&parsed, &source_map);

        // Only deduplicate against existing CONTRACT violations (same type) — not dead code
        // LLM findings are a different insight even if the line overlaps
        let existing_contract_keys: std::collections::HashSet<(String, usize)> = report.issues
            .iter()
            .filter(|i| matches!(i.issue_type, crate::report::schema::IssueType::ContractViolation))
            .filter_map(|i| i.line.map(|l| (i.file.clone(), l)))
            .collect();

        llm_issues.retain(|i| {
            !i.line.map(|l| existing_contract_keys.contains(&(i.file.clone(), l))).unwrap_or(false)
        });

        let count = llm_issues.len();
        report.issues.append(&mut llm_issues);

        if count > 0 {
            eprintln!("LLM analysis found {} additional issues.", count);
        } else {
            eprintln!("LLM analysis found no additional issues.");
        }
    }

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
