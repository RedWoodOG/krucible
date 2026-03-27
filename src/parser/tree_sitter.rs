use tree_sitter::{Parser, Node};
use anyhow::Result;
use crate::scanner::file_loader::{SourceFile, Language};
use super::language_registry::get_ts_language;

#[derive(Debug, Clone)]
pub struct FunctionDef {
    pub name: String,
    pub file: String,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct CallSite {
    pub name: String,
    pub file: String,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct Import {
    pub path: String,
    pub names: Vec<String>,
    pub file: String,
    pub line: usize,
}

#[derive(Debug)]
pub struct ParsedFile {
    pub file: String,
    pub language: Language,
    pub functions: Vec<FunctionDef>,
    pub calls: Vec<CallSite>,
    pub imports: Vec<Import>,
}

pub fn parse_file(source_file: &SourceFile) -> Result<ParsedFile> {
    let ts_lang = match get_ts_language(&source_file.language) {
        Some(l) => l,
        None => return Ok(ParsedFile {
            file: source_file.path.display().to_string(),
            language: source_file.language.clone(),
            functions: vec![],
            calls: vec![],
            imports: vec![],
        }),
    };

    let mut parser = Parser::new();
    parser.set_language(&ts_lang)?;

    let tree = parser.parse(&source_file.content, None)
        .ok_or_else(|| anyhow::anyhow!("Failed to parse {}", source_file.path.display()))?;

    let root = tree.root_node();
    let content = source_file.content.as_bytes();
    let file = source_file.path.display().to_string();

    let functions = extract_functions(root, content, &file, &source_file.language);
    let calls = extract_calls(root, content, &file);
    let imports = extract_imports(root, content, &file, &source_file.language);

    Ok(ParsedFile {
        file,
        language: source_file.language.clone(),
        functions,
        calls,
        imports,
    })
}

fn node_text<'a>(node: Node<'a>, content: &'a [u8]) -> &'a str {
    node.utf8_text(content).unwrap_or("")
}

fn node_line(node: Node) -> usize {
    node.start_position().row + 1
}

fn extract_functions(root: Node, content: &[u8], file: &str, lang: &Language) -> Vec<FunctionDef> {
    let mut fns = Vec::new();
    extract_functions_recursive(root, content, file, lang, &mut fns);
    fns
}

fn extract_functions_recursive(node: Node, content: &[u8], file: &str, lang: &Language, acc: &mut Vec<FunctionDef>) {
    let kind = node.kind();

    let name_opt: Option<String> = match lang {
        Language::TypeScript | Language::JavaScript => match kind {
            "function_declaration" | "method_definition" | "arrow_function" => {
                node.child_by_field_name("name")
                    .map(|n| node_text(n, content).to_string())
            }
            "variable_declarator" => {
                // const foo = () => {}  or  const foo = function() {}
                let val = node.child_by_field_name("value");
                if val.map(|v| matches!(v.kind(), "arrow_function" | "function")).unwrap_or(false) {
                    node.child_by_field_name("name")
                        .map(|n| node_text(n, content).to_string())
                } else {
                    None
                }
            }
            _ => None,
        },
        Language::Rust => match kind {
            "function_item" => {
                node.child_by_field_name("name")
                    .map(|n| node_text(n, content).to_string())
            }
            _ => None,
        },
        _ => None,
    };

    if let Some(name) = name_opt {
        if !name.is_empty() {
            acc.push(FunctionDef {
                name,
                file: file.to_string(),
                line: node_line(node),
            });
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        extract_functions_recursive(child, content, file, lang, acc);
    }
}

fn extract_calls(root: Node, content: &[u8], file: &str) -> Vec<CallSite> {
    let mut calls = Vec::new();
    extract_calls_recursive(root, content, file, &mut calls);
    calls
}

fn extract_calls_recursive(node: Node, content: &[u8], file: &str, acc: &mut Vec<CallSite>) {
    if node.kind() == "call_expression" {
        let func_node = node.child_by_field_name("function");
        if let Some(f) = func_node {
            let name = match f.kind() {
                "identifier" => node_text(f, content).to_string(),
                "member_expression" => {
                    // foo.bar() — grab the property
                    f.child_by_field_name("property")
                        .map(|p| node_text(p, content).to_string())
                        .unwrap_or_default()
                }
                _ => node_text(f, content).to_string(),
            };
            if !name.is_empty() {
                acc.push(CallSite {
                    name,
                    file: file.to_string(),
                    line: node_line(node),
                });
            }
        }
    }

    // Rust function calls
    if node.kind() == "call_expression" || node.kind() == "macro_invocation" {
        // already handled above for TS; Rust shares call_expression kind
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        extract_calls_recursive(child, content, file, acc);
    }
}

fn extract_imports(root: Node, content: &[u8], file: &str, lang: &Language) -> Vec<Import> {
    let mut imports = Vec::new();
    extract_imports_recursive(root, content, file, lang, &mut imports);
    imports
}

fn extract_imports_recursive(node: Node, content: &[u8], file: &str, lang: &Language, acc: &mut Vec<Import>) {
    match lang {
        Language::TypeScript | Language::JavaScript => {
            if node.kind() == "import_statement" {
                let path = node.child_by_field_name("source")
                    .map(|n| node_text(n, content).trim_matches('"').trim_matches('\'').to_string())
                    .unwrap_or_default();

                let names: Vec<String> = {
                    let mut ns = Vec::new();
                    let mut c = node.walk();
                    for child in node.children(&mut c) {
                        if child.kind() == "import_clause" || child.kind() == "named_imports" {
                            let mut c2 = child.walk();
                            for n in child.children(&mut c2) {
                                if n.kind() == "identifier" || n.kind() == "import_specifier" {
                                    ns.push(node_text(n, content).to_string());
                                }
                            }
                        }
                    }
                    ns
                };

                acc.push(Import {
                    path,
                    names,
                    file: file.to_string(),
                    line: node_line(node),
                });
            }
        }
        Language::Rust => {
            if node.kind() == "use_declaration" {
                let path = node_text(node, content)
                    .trim_start_matches("use ")
                    .trim_end_matches(';')
                    .to_string();
                acc.push(Import {
                    path,
                    names: vec![],
                    file: file.to_string(),
                    line: node_line(node),
                });
            }
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        extract_imports_recursive(child, content, file, lang, acc);
    }
}
