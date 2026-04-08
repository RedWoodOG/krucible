use std::collections::HashSet;
use crate::parser::tree_sitter::{ParsedFile, FunctionKind};
use crate::report::schema::{Issue, IssueType, Severity};

/// Cross-reference all function definitions against all call sites.
/// Any function defined but never called anywhere = dead code / fake wiring.
pub fn analyze(files: &[ParsedFile]) -> Vec<Issue> {
    let mut issues = Vec::new();

    // Collect all function names defined across the entire repo
    let all_defs: Vec<_> = files.iter()
        .flat_map(|f| f.functions.iter())
        .collect();

    // Collect all call site names across the entire repo
    let all_calls: HashSet<String> = files.iter()
        .flat_map(|f| f.calls.iter().map(|c| c.name.clone()))
        .collect();

    // Skip these — common entry points / lifecycle functions that are called by runtime
    let ignored = [
        "main", "new", "default", "drop", "fmt", "from", "into",
        "clone", "hash", "eq", "ne", "cmp", "partial_cmp",
        // TS/React lifecycle
        "render", "constructor", "componentDidMount", "componentWillUnmount",
        "useEffect", "useState", "useCallback", "useMemo", "useRef",
        // Express/common
        "listen", "use", "get", "post", "put", "delete", "patch",
        "on", "emit", "connect", "close",
        // Internal helper constructors/emitters used by serialization paths.
        "sarif_rule",
    ];

    for def in &all_defs {
        let name = &def.name;

        // Skip short/generic names and known entry points
        if name.len() < 3 || ignored.contains(&name.as_str()) {
            continue;
        }

        // Skip private-style names (single underscore prefix is intentional in Rust)
        if name.starts_with("__") {
            continue;
        }

        // Public functions may be entry points for external callers/framework runtime.
        // Tauri commands are invoked by runtime, not Rust call sites.
        if matches!(def.kind, FunctionKind::Public | FunctionKind::TauriCommand) {
            continue;
        }

        if !all_calls.contains(name) {
            issues.push(Issue {
                issue_type: IssueType::DeadCode,
                severity: Severity::Medium,
                file: def.file.clone(),
                line: Some(def.line),
                message: format!("Function defined but never called: `{name}()`"),
                claim: Some(format!("`{name}` is defined as a callable function")),
                reality: Some("No call site found anywhere in the repo".into()),
            });
        }
    }

    issues
}
