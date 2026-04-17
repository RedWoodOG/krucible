use std::collections::HashSet;
use regex::Regex;
use crate::parser::tree_sitter::ParsedFile;
use crate::report::schema::{Issue, IssueType, Severity};

/// Tauri-specific wiring analysis.
///
/// Rules:
/// 1. Only #[tauri::command] annotated functions are Tauri commands — pub fn alone is not enough
/// 2. A #[tauri::command] function not in generate_handler! = unreachable from frontend
pub fn analyze(files: &[ParsedFile], source_map: &std::collections::HashMap<String, String>) -> Vec<Issue> {
    let mut issues = Vec::new();

    // Collect all Tauri commands across the repo (ONLY #[tauri::command] annotated)
    let all_commands: Vec<_> = files.iter()
        .flat_map(|f| f.tauri_commands())
        .collect();

    if all_commands.is_empty() {
        // Not a Tauri app — nothing to check
        return issues;
    }

    // Collect all registered command names from generate_handler! macro calls
    let registered = collect_registered_from_sources(source_map);

    // Collect frontend invoke() targets from TS/JS source
    let frontend_invocations = collect_frontend_invocations_from_sources(source_map);

    for cmd in &all_commands {
        let cmd_name = normalize_command_name(&cmd.name);

        // Check 1: command annotated but not in generate_handler!
        // Only flag this if we actually found a generate_handler! somewhere
        // (if registered is empty, we couldn't detect the macro — don't false-positive)
        if !registered.is_empty() && !registered.contains(&cmd_name) {
            issues.push(Issue {
                issue_type: IssueType::FakeWiring,
                severity: Severity::High,
                file: cmd.file.clone(),
                line: Some(cmd.line),
                message: format!(
                    "Tauri command `{}` annotated but not registered in generate_handler!",
                    cmd.name
                ),
                claim: Some(format!("`{}` is annotated #[tauri::command]", cmd.name)),
                reality: Some("Not found in generate_handler![] — frontend cannot invoke this command".into()),
            });
            continue;
        }

        // Check 2: registered command with no frontend invocation
        // Only flag if we found actual invoke() calls (non-empty frontend map)
        if !frontend_invocations.is_empty() && !frontend_invocations.contains(&cmd_name) {
            issues.push(Issue {
                issue_type: IssueType::DeadCode,
                severity: Severity::Medium,
                file: cmd.file.clone(),
                line: Some(cmd.line),
                message: format!(
                    "Tauri command `{}` registered but never invoked from frontend",
                    cmd.name
                ),
                claim: Some(format!("`{}` is registered and available to frontend", cmd.name)),
                reality: Some(format!("No invoke(\"{}\", ...) call found in TS/JS files", cmd.name)),
            });
        }
    }

    issues
}

/// Parse all Rust source files for generate_handler![...] and extract command names.
fn collect_registered_from_sources(
    source_map: &std::collections::HashMap<String, String>,
) -> HashSet<String> {
    let mut registered = HashSet::new();

    let handler_re = Regex::new(
        r"generate_handler!\s*[\[!(\s]*([a-zA-Z0-9_,\s:]+)[\]!)\s]*"
    ).unwrap();
    let ident_re = Regex::new(r"\b([a-z_][a-z0-9_]*)\b").unwrap();

    for (path, source) in source_map {
        if !path.ends_with(".rs") {
            continue;
        }
        for cap in handler_re.captures_iter(source) {
            let args = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            for ident in ident_re.find_iter(args) {
                let name = normalize_command_name(ident.as_str());
                registered.insert(name);
            }
        }
    }

    registered
}

/// Parse TS/JS source for invoke("command_name", ...) and extract command name strings.
fn collect_frontend_invocations_from_sources(
    source_map: &std::collections::HashMap<String, String>,
) -> HashSet<String> {
    let mut invocations = HashSet::new();

    // Match: invoke("command_name") or invoke('command_name')
    let invoke_re = Regex::new(r#"invoke\s*\(\s*["']([a-z_][a-z0-9_]*)["']"#).unwrap();

    for (path, source) in source_map {
        if !path.ends_with(".ts") && !path.ends_with(".tsx")
            && !path.ends_with(".js") && !path.ends_with(".jsx") {
            continue;
        }
        for cap in invoke_re.captures_iter(source) {
            if let Some(name) = cap.get(1) {
                invocations.insert(normalize_command_name(name.as_str()));
            }
        }
    }

    invocations
}

fn normalize_command_name(name: &str) -> String {
    name.to_lowercase().replace('-', "_")
}
