use regex::Regex;
use crate::scanner::file_loader::SourceFile;
use crate::report::schema::{Issue, IssueType, Severity};

struct SlopPattern {
    pattern: &'static str,
    severity: Severity,
    message: &'static str,
}

/// Detect AI slop patterns: TODOs, mocks, placeholders, empty stubs
pub fn analyze(files: &[SourceFile]) -> Vec<Issue> {
    let mut issues = Vec::new();

    let patterns = vec![
        SlopPattern {
            pattern: r"//\s*(TODO|FIXME|HACK|XXX|PLACEHOLDER|IMPLEMENT ME)",
            severity: Severity::High,
            message: "Unresolved TODO/placeholder",
        },
        SlopPattern {
            pattern: r"(mock|stub|fake|dummy|placeholder)\s*[=({]",
            severity: Severity::High,
            message: "Mock/stub logic in production path",
        },
        SlopPattern {
            pattern: r"throw new Error.*not implemented",
            severity: Severity::High,
            message: "Unimplemented function stub",
        },
        SlopPattern {
            pattern: r"unimplemented!\(\)",
            severity: Severity::High,
            message: "Rust unimplemented! macro — not production ready",
        },
        SlopPattern {
            pattern: r"todo!\(\)",
            severity: Severity::Medium,
            message: "Rust todo! macro left in code",
        },
        SlopPattern {
            pattern: r"(?i)//\s*(temporary|temp fix|will fix|revisit)",
            severity: Severity::Medium,
            message: "Temporary fix comment",
        },
        SlopPattern {
            pattern: r"console\.(log|warn|error).*debug",
            severity: Severity::Low,
            message: "Debug logging left in code",
        },
    ];

    let compiled: Vec<(Regex, &Severity, &str)> = patterns
        .iter()
        .map(|p| (Regex::new(p.pattern).unwrap(), &p.severity, p.message))
        .collect();

    for file in files {
        let is_slop_rs = file
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case("slop.rs"));
        for (line_num, line) in file.content.lines().enumerate() {
            // Avoid matching this detector's own regex declarations in slop.rs only.
            if is_slop_rs
                && (line.contains("pattern: r\"")
                    || line.contains(concat!("Regex::new(r", "\"")))
            {
                continue;
            }
            for (re, severity, msg) in &compiled {
                if re.is_match(line) {
                    issues.push(Issue {
                        issue_type: IssueType::AiSlop,
                        severity: (*severity).clone(),
                        file: file.path.display().to_string(),
                        line: Some(line_num + 1),
                        message: format!("{}: `{}`", msg, line.trim()),
                        claim: None,
                        reality: None,
                    });
                }
            }
        }
    }

    issues
}
