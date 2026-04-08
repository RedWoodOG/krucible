use crate::ir::model::{IrCallKind, IrRepo};
use crate::report::schema::{Issue, IssueType, Severity};
use regex::Regex;

/// Contract violations: functions that claim to do something but structurally can't.
/// This is the Reality Gap — what a function's name/docs promise vs what it actually does.
pub fn analyze(ir_repo: &IrRepo) -> Vec<Issue> {
    let mut issues = Vec::new();

    for file in &ir_repo.files {
        for func in &file.functions {
            let gaps = check_reality_gap(func, &file.calls);
            for gap in gaps {
                issues.push(Issue {
                    issue_type: IssueType::ContractViolation,
                    severity: Severity::High,
                    file: file.path.clone(),
                    line: Some(func.start_line),
                    message: format!("Reality gap in `{}()`", func.name),
                    claim: Some(gap.claim),
                    reality: Some(gap.reality),
                });
            }
        }
    }

    issues
}

struct Gap {
    claim: String,
    reality: String,
}

/// Check if a function's name implies behavior that isn't present in the function body.
fn check_reality_gap(
    func: &crate::ir::model::IrFunction,
    calls: &[crate::ir::model::IrCall],
) -> Vec<Gap> {
    let mut gaps = Vec::new();
    let name = &func.name;
    let name_lower = name.to_lowercase();

    // Calls that happen within the function's own line span.
    let calls_in_fn: Vec<&crate::ir::model::IrCall> = calls
        .iter()
        .filter(|c| c.line >= func.start_line && c.line <= func.end_line)
        .collect();

    // --- DB / Persistence ---
    if matches_any(&name_lower, &["save", "create", "insert", "persist", "store", "write_to"]) {
        let has_persistence_signal = calls_in_fn.iter().any(|c| {
            matches!(c.kind, IrCallKind::Persistence | IrCallKind::Io)
        });
        if !has_persistence_signal {
            gaps.push(Gap {
                claim: format!("`{}` implies writing/persisting data", name),
                reality: "No database call, query, or persistence operation found".into(),
            });
        }
    }

    // --- Auth / Validation ---
    if matches_any(&name_lower, &["authenticate", "authorize", "verify", "check_permission"]) {
        let has_auth_signal = calls_in_fn.iter().any(|c| matches!(c.kind, IrCallKind::Auth));
        if !has_auth_signal {
            gaps.push(Gap {
                claim: format!("`{}` implies authentication or validation logic", name),
                reality: "No auth, hashing, token, or permission check found".into(),
            });
        }
    }

    // --- Network / API ---
    if matches_any(&name_lower, &["send_request", "call_api", "post_to", "get_from", "http_"]) {
        let has_net_signal = calls_in_fn.iter().any(|c| matches!(c.kind, IrCallKind::Network));
        if !has_net_signal {
            gaps.push(Gap {
                claim: format!("`{}` implies making a network/HTTP request", name),
                reality: "No HTTP client call, fetch, or request found".into(),
            });
        }
    }

    // --- File I/O ---
    if matches_any(&name_lower, &["read_file", "write_file", "load_from_disk", "save_to_disk"]) {
        let has_io_signal = calls_in_fn.iter().any(|c| matches!(c.kind, IrCallKind::Io));
        if !has_io_signal {
            gaps.push(Gap {
                claim: format!("`{}` implies file I/O operation", name),
                reality: "No file read, write, or open operation found".into(),
            });
        }
    }

    // --- Email / Notifications ---
    if matches_any(&name_lower, &["send_email", "notify", "send_notification", "email_user"]) {
        let has_notify_signal = calls_in_fn
            .iter()
            .any(|c| matches!(c.kind, IrCallKind::Notification));
        if !has_notify_signal {
            gaps.push(Gap {
                claim: format!("`{}` implies sending a notification or email", name),
                reality: "No mail/notification client call found".into(),
            });
        }
    }

    gaps
}

fn matches_any(name: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|p| name.contains(p))
}

/// Scan for functions that are named with action verbs but have suspiciously few calls inside them.
/// A "createUser" with 0 sub-calls is almost certainly fake wiring.
pub fn analyze_empty_stubs(ir_repo: &IrRepo) -> Vec<Issue> {
    let mut issues = Vec::new();

    let action_prefixes = Regex::new(
        r"^(create|update|delete|save|send|process|handle|run|execute|submit|upload|download|sync|load|generate|build)"
    ).unwrap();

    for file in &ir_repo.files {
        for func in &file.functions {
            if !action_prefixes.is_match(&func.name.to_lowercase()) {
                continue;
            }

            // Count calls that happen in the vicinity of this function
            // (calls inside this function's line span)
            let calls_in_fn = file
                .calls
                .iter()
                .filter(|c| c.line >= func.start_line && c.line <= func.end_line)
                .count();

            if calls_in_fn == 0 {
                issues.push(Issue {
                    issue_type: IssueType::FakeWiring,
                    severity: Severity::High,
                    file: file.path.clone(),
                    line: Some(func.start_line),
                    message: format!("Action function `{}()` makes zero calls — likely empty stub", func.name),
                    claim: Some(format!("`{}` is named as an action (create/update/send/etc.)", func.name)),
                    reality: Some("Function body contains no function calls — likely placeholder logic".into()),
                });
            }
        }
    }

    issues
}
