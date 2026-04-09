use crate::report::schema::{Issue, IssueType, Severity};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn analyze(repo_path: &Path) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(run_cargo_check(repo_path));
    issues.extend(run_tsc(repo_path));
    issues
}

fn run_cargo_check(repo_path: &Path) -> Vec<Issue> {
    let cargo_toml = repo_path.join("Cargo.toml");
    if !cargo_toml.exists() {
        return Vec::new();
    }

    let output = Command::new("cargo")
        .arg("check")
        .arg("--message-format")
        .arg("json")
        .current_dir(repo_path)
        .output();

    let Ok(output) = output else {
        return Vec::new();
    };

    let mut issues = parse_cargo_json_messages(repo_path, &output.stdout);

    // Fallback: if command invocation itself fails unusually, surface stderr summary.
    if !output.status.success() && issues.is_empty() {
        let summary = String::from_utf8_lossy(&output.stderr);
        let line = summary.lines().next().unwrap_or("cargo check failed");
        issues.push(Issue {
            issue_type: IssueType::CompilerDiagnostic,
            severity: Severity::High,
            file: repo_path.display().to_string(),
            line: None,
            message: "Rust compiler check failed".into(),
            claim: Some("Rust sources compile successfully".into()),
            reality: Some(line.to_string()),
        });
    }

    issues
}

fn run_tsc(repo_path: &Path) -> Vec<Issue> {
    let tsconfig = repo_path.join("tsconfig.json");
    if !tsconfig.exists() {
        return Vec::new();
    }

    // Prefer local tsc via npx for project-consistent typescript.
    let output = Command::new("npx")
        .arg("--yes")
        .arg("tsc")
        .arg("--noEmit")
        .arg("--pretty")
        .arg("false")
        .current_dir(repo_path)
        .output();

    let Ok(output) = output else {
        return Vec::new();
    };

    let mut issues = parse_tsc_text_output(repo_path, &output.stdout, &output.stderr);
    if !output.status.success() && issues.is_empty() {
        let err = String::from_utf8_lossy(&output.stderr);
        let line = err.lines().next().unwrap_or("tsc failed");
        issues.push(Issue {
            issue_type: IssueType::CompilerDiagnostic,
            severity: Severity::High,
            file: repo_path.display().to_string(),
            line: None,
            message: "TypeScript compiler check failed".into(),
            claim: Some("TypeScript sources type-check successfully".into()),
            reality: Some(line.to_string()),
        });
    }
    issues
}

#[derive(Debug, Deserialize)]
struct CargoMessage {
    reason: String,
    message: Option<CargoDiagnostic>,
}

#[derive(Debug, Deserialize)]
struct CargoDiagnostic {
    level: String,
    message: String,
    spans: Vec<CargoSpan>,
    code: Option<CargoCode>,
}

#[derive(Debug, Deserialize)]
struct CargoCode {
    code: String,
}

#[derive(Debug, Deserialize)]
struct CargoSpan {
    file_name: String,
    line_start: usize,
    is_primary: bool,
}

fn parse_cargo_json_messages(repo_path: &Path, stdout: &[u8]) -> Vec<Issue> {
    let text = String::from_utf8_lossy(stdout);
    text.lines()
        .filter_map(|line| serde_json::from_str::<CargoMessage>(line).ok())
        .filter(|msg| msg.reason == "compiler-message")
        .filter_map(|msg| msg.message)
        .filter(|diag| matches!(diag.level.as_str(), "error" | "warning"))
        .map(|diag| {
            let primary = diag
                .spans
                .iter()
                .find(|span| span.is_primary)
                .or_else(|| diag.spans.first());
            let (file, line) = if let Some(span) = primary {
                (
                    normalize_path(repo_path, Path::new(&span.file_name)),
                    Some(span.line_start),
                )
            } else {
                (repo_path.display().to_string(), None)
            };
            let code_suffix = diag
                .code
                .as_ref()
                .map(|c| format!(" ({})", c.code))
                .unwrap_or_default();
            let severity = if diag.level == "error" {
                Severity::High
            } else {
                Severity::Medium
            };
            Issue {
                issue_type: IssueType::CompilerDiagnostic,
                severity,
                file,
                line,
                message: format!("rustc {}{}: {}", diag.level, code_suffix, diag.message),
                claim: Some("Rust code compiles cleanly".into()),
                reality: Some("Compiler reported a diagnostic for this location".into()),
            }
        })
        .collect()
}

fn parse_tsc_text_output(repo_path: &Path, stdout: &[u8], stderr: &[u8]) -> Vec<Issue> {
    let mut issues = Vec::new();
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(stdout),
        String::from_utf8_lossy(stderr)
    );

    for line in text.lines() {
        // Typical: src/file.ts(10,5): error TS2322: message
        let Some((path_and_pos, rhs)) = line.split_once(": error ") else {
            // Also handle warnings printed similarly.
            let Some((path_and_pos, rhs)) = line.split_once(": warning ") else {
                continue;
            };
            if let Some((file, line_no, code, msg)) = parse_tsc_line(path_and_pos, rhs) {
                issues.push(Issue {
                    issue_type: IssueType::CompilerDiagnostic,
                    severity: Severity::Medium,
                    file: normalize_path(repo_path, &file),
                    line: Some(line_no),
                    message: format!("tsc warning {}: {}", code, msg),
                    claim: Some("TypeScript code type-checks without warnings".into()),
                    reality: Some("TypeScript compiler warning reported".into()),
                });
            }
            continue;
        };

        if let Some((file, line_no, code, msg)) = parse_tsc_line(path_and_pos, rhs) {
            issues.push(Issue {
                issue_type: IssueType::CompilerDiagnostic,
                severity: Severity::High,
                file: normalize_path(repo_path, &file),
                line: Some(line_no),
                message: format!("tsc error {}: {}", code, msg),
                claim: Some("TypeScript code type-checks cleanly".into()),
                reality: Some("TypeScript compiler error reported".into()),
            });
        }
    }

    issues
}

fn parse_tsc_line(path_and_pos: &str, rhs: &str) -> Option<(PathBuf, usize, String, String)> {
    let open = path_and_pos.rfind('(')?;
    let close = path_and_pos.rfind(')')?;
    if close <= open {
        return None;
    }
    let file = PathBuf::from(path_and_pos[..open].trim());
    let coords = &path_and_pos[open + 1..close];
    let mut coords_iter = coords.split(',');
    let line_no = coords_iter.next()?.trim().parse::<usize>().ok()?;
    let mut rhs_parts = rhs.splitn(2, ':');
    let code = rhs_parts.next()?.trim().to_string();
    let msg = rhs_parts.next().unwrap_or("").trim().to_string();
    Some((file, line_no, code, msg))
}

fn normalize_path(repo_path: &Path, path: &Path) -> String {
    if path.is_absolute() {
        if let Ok(stripped) = path.strip_prefix(repo_path) {
            return stripped.display().to_string();
        }
        return path.display().to_string();
    }
    path.display().to_string()
}
