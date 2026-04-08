use regex::Regex;
use crate::ir::model::{IrCallKind, IrRepo};
use crate::scanner::file_loader::SourceFile;
use crate::report::schema::{Issue, IssueType, Severity};

/// Detect execution path integrity issues:
/// - async functions that never await
/// - unhandled promise chains (no .catch)
/// - fire-and-forget network calls
pub fn analyze(files: &[SourceFile], repo: &IrRepo) -> Vec<Issue> {
    let mut issues = Vec::new();

    let async_fn = Regex::new(r"async\s+function\s+(\w+)").unwrap();
    let has_await = Regex::new(r"\bawait\b").unwrap();
    let promise_then = Regex::new(r"\.then\(").unwrap();
    let unhandled_net = Regex::new(r"^\s*(fetch|axios\.\w+)\(").unwrap();

    for file in files {
        let content = &file.content;
        let file_str = file.path.display().to_string();

        // 1. Async functions without await
        for cap in async_fn.captures_iter(content) {
            let fn_name = cap.get(1).map(|m| m.as_str()).unwrap_or("unknown");
            let pos = cap.get(0).unwrap().start();
            let line = content[..pos].lines().count() + 1;

            // Grab next 25 lines as function body approximation
            let snippet: String = content[pos..].lines().take(25).collect::<Vec<_>>().join("\n");

            if !has_await.is_match(&snippet) {
                issues.push(Issue {
                    issue_type: IssueType::UnresolvedAsync,
                    severity: Severity::Medium,
                    file: file_str.clone(),
                    line: Some(line),
                    message: format!("Async function `{fn_name}` never awaits — async keyword is dead weight"),
                    claim: Some(format!("`{fn_name}` declared async, implying async operations")),
                    reality: Some("No await found in function body — runs synchronously anyway".into()),
                });
            }
        }

        // 2. .then() chains — check if .catch appears nearby
        for cap in promise_then.find_iter(content) {
            let pos = cap.start();
            let line_start = content[..pos].rfind('\n').map(|i| i + 1).unwrap_or(0);
            let line_end = content[pos..]
                .find('\n')
                .map(|i| pos + i)
                .unwrap_or(content.len());
            let line_text = content[line_start..line_end].trim();

            // Ignore comments and detector-internal regex declarations/usages.
            if line_text.starts_with("//")
                || line_text.contains("Regex::new(")
                || line_text.contains("promise_then")
            {
                continue;
            }

            // Ignore escaped `.then(` patterns (e.g. regex literals like r"\.then\(").
            if pos > 0 && content.as_bytes()[pos - 1] == b'\\' {
                continue;
            }
            let line = content[..pos].lines().count() + 1;

            // Look at surrounding 300 chars for .catch
            let end = std::cmp::min(pos + 300, content.len());
            let snippet = &content[pos..end];

            if !snippet.contains(".catch(") && !snippet.contains("catch(") {
                issues.push(Issue {
                    issue_type: IssueType::UnresolvedAsync,
                    severity: Severity::Medium,
                    file: file_str.clone(),
                    line: Some(line),
                    message: "Promise `.then()` with no `.catch()` — rejection silently dropped".into(),
                    claim: Some("Promise chain handles result".into()),
                    reality: Some("No error handler — failed promise will be swallowed".into()),
                });
            }
        }

        // 3. Network calls not awaited and not chained
        for (line_num, line_str) in content.lines().enumerate() {
            if unhandled_net.is_match(line_str) {
                let trimmed = line_str.trim();
                // Check if the line itself starts with await or is assigned
                let is_handled = trimmed.starts_with("await ")
                    || trimmed.contains("= fetch(")
                    || trimmed.contains("= axios.")
                    || trimmed.starts_with("const ")
                    || trimmed.starts_with("let ")
                    || trimmed.starts_with("return ");

                if !is_handled {
                    issues.push(Issue {
                        issue_type: IssueType::UnresolvedAsync,
                        severity: Severity::High,
                        file: file_str.clone(),
                        line: Some(line_num + 1),
                        message: "Network call result not captured — fire and forget".into(),
                        claim: Some("Network request is initiated".into()),
                        reality: Some("Result is never awaited or handled — response is lost".into()),
                    });
                }
            }
        }
    }

    // Add IR-assisted structural checks.
    issues.extend(analyze_ir(repo));

    // Deduplicate by file+line
    issues.dedup_by(|a, b| a.file == b.file && a.line == b.line);

    issues
}

/// IR-assisted execution checks:
/// - action-like async functions with no async-like calls
/// - promise `.then()` chains without nearby `.catch()`
///
/// This complements the text-based analyzer with structural context.
pub fn analyze_ir(repo: &IrRepo) -> Vec<Issue> {
    let mut issues = Vec::new();

    for file in &repo.files {
        // Promise then/catch structural check per file.
        let then_lines: Vec<usize> = file
            .calls
            .iter()
            .filter(|c| matches!(c.kind, IrCallKind::PromiseThen))
            .map(|c| c.line)
            .collect();
        let catch_lines: Vec<usize> = file
            .calls
            .iter()
            .filter(|c| matches!(c.kind, IrCallKind::PromiseCatch))
            .map(|c| c.line)
            .collect();

        for then_line in then_lines {
            let has_nearby_catch = catch_lines.iter().any(|catch_line| {
                let distance = if *catch_line > then_line {
                    *catch_line - then_line
                } else {
                    then_line - *catch_line
                };
                distance <= 12
            });

            if !has_nearby_catch {
                issues.push(Issue {
                    issue_type: IssueType::UnresolvedAsync,
                    severity: Severity::Medium,
                    file: file.path.clone(),
                    line: Some(then_line),
                    message: "Promise `.then()` with no nearby `.catch()` — rejection may be dropped".into(),
                    claim: Some("Promise chain handles result".into()),
                    reality: Some("No nearby `.catch()` call detected in structural call graph".into()),
                });
            }
        }
    }

    issues
}
