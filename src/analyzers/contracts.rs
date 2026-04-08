use crate::parser::tree_sitter::{FunctionDef, ParsedFile};
use crate::report::schema::{Issue, IssueType, Severity};
use regex::Regex;

/// Contract violations: functions that claim to do something but structurally can't.
/// This is the Reality Gap — what a function's name/docs promise vs what it actually does.
pub fn analyze(files: &[ParsedFile]) -> Vec<Issue> {
    let mut issues = Vec::new();

    for file in files {
        for func in &file.functions {
            let gaps = check_reality_gap(func, file);
            for gap in gaps {
                issues.push(Issue {
                    issue_type: IssueType::ContractViolation,
                    severity: Severity::High,
                    file: file.file.clone(),
                    line: Some(func.line),
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
fn check_reality_gap(func: &FunctionDef, file: &ParsedFile) -> Vec<Gap> {
    let mut gaps = Vec::new();
    let name = &func.name;
    let name_lower = name.to_lowercase();

    // Calls that happen within the function's own line span.
    let calls_in_fn: Vec<&str> = file
        .calls
        .iter()
        .filter(|c| c.line >= func.line && c.line <= func.end_line)
        .map(|c| c.name.as_str())
        .collect();

    // --- DB / Persistence ---
    if matches_any(&name_lower, &["save", "create", "insert", "persist", "store", "write_to"]) {
        let persistence_calls = [
            "query",
            "execute",
            "insert",
            "save",
            "create",
            "db",
            "pool",
            "transaction",
            "commit",
            "collection",
            "find_one",
            "save_one",
            "insert_one",
            "prisma",
            "sequelize",
            "mongoose",
            "knex",
            "sql",
            // File persistence also satisfies "save/create/store" intent.
            "write",
            "write_all",
            "write_to_string",
            "file",
            "fs",
        ];
        if !calls_in_fn
            .iter()
            .any(|c| persistence_calls.iter().any(|d| c.to_lowercase().contains(d)))
        {
            gaps.push(Gap {
                claim: format!("`{}` implies writing/persisting data", name),
                reality: "No database call, query, or persistence operation found".into(),
            });
        }
    }

    // --- Auth / Validation ---
    if matches_any(&name_lower, &["authenticate", "authorize", "verify", "check_permission"]) {
        let auth_calls = ["verify", "compare", "bcrypt", "jwt", "token", "hash",
                          "password", "secret", "auth", "permission", "role", "decode"];
        if !calls_in_fn.iter().any(|c| auth_calls.iter().any(|d| c.to_lowercase().contains(d))) {
            gaps.push(Gap {
                claim: format!("`{}` implies authentication or validation logic", name),
                reality: "No auth, hashing, token, or permission check found".into(),
            });
        }
    }

    // --- Network / API ---
    if matches_any(&name_lower, &["send_request", "call_api", "post_to", "get_from", "http_"]) {
        let net_calls = ["fetch", "request", "axios", "http", "get", "post", "put",
                         "delete", "patch", "send", "reqwest", "hyper", "surf", "ureq"];
        if !calls_in_fn.iter().any(|c| net_calls.iter().any(|d| c.to_lowercase().contains(d))) {
            gaps.push(Gap {
                claim: format!("`{}` implies making a network/HTTP request", name),
                reality: "No HTTP client call, fetch, or request found".into(),
            });
        }
    }

    // --- File I/O ---
    if matches_any(&name_lower, &["read_file", "write_file", "load_from_disk", "save_to_disk"]) {
        let io_calls = ["read", "write", "open", "file", "fs", "path", "read_to_string",
                        "write_all", "create", "read_dir", "read_file", "write_file"];
        if !calls_in_fn.iter().any(|c| io_calls.iter().any(|d| c.to_lowercase().contains(d))) {
            gaps.push(Gap {
                claim: format!("`{}` implies file I/O operation", name),
                reality: "No file read, write, or open operation found".into(),
            });
        }
    }

    // --- Email / Notifications ---
    if matches_any(&name_lower, &["send_email", "notify", "send_notification", "email_user"]) {
        let notify_calls = ["send", "mail", "email", "smtp", "notify", "push", "sendgrid",
                            "mailgun", "ses", "message", "notification"];
        if !calls_in_fn.iter().any(|c| notify_calls.iter().any(|d| c.to_lowercase().contains(d))) {
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
pub fn analyze_empty_stubs(files: &[ParsedFile]) -> Vec<Issue> {
    let mut issues = Vec::new();

    let action_prefixes = Regex::new(
        r"^(create|update|delete|save|send|process|handle|run|execute|submit|upload|download|sync|load|generate|build)"
    ).unwrap();

    for file in files {
        for func in &file.functions {
            if !action_prefixes.is_match(&func.name.to_lowercase()) {
                continue;
            }

            // Count calls that happen in the vicinity of this function
            // (calls inside this function's line span)
            let calls_in_fn = file
                .calls
                .iter()
                .filter(|c| c.line >= func.line && c.line <= func.end_line)
                .count();

            if calls_in_fn == 0 {
                issues.push(Issue {
                    issue_type: IssueType::FakeWiring,
                    severity: Severity::High,
                    file: file.file.clone(),
                    line: Some(func.line),
                    message: format!("Action function `{}()` makes zero calls — likely empty stub", func.name),
                    claim: Some(format!("`{}` is named as an action (create/update/send/etc.)", func.name)),
                    reality: Some("Function body contains no function calls — likely placeholder logic".into()),
                });
            }
        }
    }

    issues
}
