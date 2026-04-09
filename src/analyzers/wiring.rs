use crate::ir::builder as ir_builder;
use crate::ir::model::{IrRepo, IrVisibility};
use crate::ir::symbols::{ResolutionConfidence, SymbolTable};
use crate::parser::tree_sitter::ParsedFile;
use crate::report::schema::{Issue, IssueType, Severity};

/// Cross-reference all function definitions against all call sites.
/// Any function defined but never called anywhere = dead code / fake wiring.
pub fn analyze(files: &[ParsedFile]) -> Vec<Issue> {
    let repo = ir_builder::from_parsed_files(files);
    analyze_ir(&repo)
}

/// IR-backed wiring analyzer.
/// This is the first analyzer migrated to the normalized IR layer.
pub fn analyze_ir(repo: &IrRepo) -> Vec<Issue> {
    let mut issues = Vec::new();

    // Collect all function definitions across the entire repo
    let all_defs: Vec<_> = repo.all_functions().collect();
    let symbol_table = SymbolTable::from_repo(repo);

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

        // Rust #[test] / #[tokio::test] functions are framework entry points.
        if def
            .attributes
            .iter()
            .any(|attr| is_rust_test_attribute(attr))
        {
            continue;
        }

        // Public functions may be entry points for external callers/framework runtime.
        // Tauri commands are invoked by runtime, not Rust call sites.
        if matches!(def.visibility, IrVisibility::Public | IrVisibility::RuntimeExposed) {
            continue;
        }

        let has_reference = symbol_table.has_confident_reference(
            name,
            &def.file,
            def.start_line,
            ResolutionConfidence::High,
        ) || symbol_table.has_confident_reference(
            name,
            &def.file,
            def.start_line,
            ResolutionConfidence::Medium,
        );

        if !has_reference {
            issues.push(Issue {
                issue_type: IssueType::DeadCode,
                severity: Severity::Medium,
                file: def.file.clone(),
                line: Some(def.start_line),
                message: format!("Function defined but never called: `{name}()`"),
                claim: Some(format!("`{name}` is defined as a callable function")),
                reality: Some("No call site found anywhere in the repo".into()),
            });
        }
    }

    issues
}

fn is_rust_test_attribute(attr: &str) -> bool {
    let t = attr.trim();
    t.starts_with("#[test]")
        || t.starts_with("#[test(")
        || t.contains("::test]")
        || t.contains("::test(")
}
