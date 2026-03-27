use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use anyhow::Result;

#[derive(Debug)]
pub struct SourceFile {
    pub path: PathBuf,
    pub language: Language,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Language {
    TypeScript,
    JavaScript,
    Rust,
    Unknown,
}

impl std::fmt::Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Language::TypeScript => write!(f, "typescript"),
            Language::JavaScript => write!(f, "javascript"),
            Language::Rust => write!(f, "rust"),
            Language::Unknown => write!(f, "unknown"),
        }
    }
}

fn detect_language(path: &Path) -> Language {
    match path.extension().and_then(|e| e.to_str()) {
        Some("ts") | Some("tsx") => Language::TypeScript,
        Some("js") | Some("jsx") | Some("mjs") => Language::JavaScript,
        Some("rs") => Language::Rust,
        _ => Language::Unknown,
    }
}

fn is_ignored(path: &Path) -> bool {
    let ignored_dirs = ["node_modules", ".git", "target", "dist", "build", ".next"];
    path.components().any(|c| {
        ignored_dirs.iter().any(|d| c.as_os_str() == *d)
    })
}

pub fn load_files(root: &Path) -> Result<Vec<SourceFile>> {
    let mut files = Vec::new();

    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();

        if is_ignored(path) {
            continue;
        }

        let lang = detect_language(path);
        if lang == Language::Unknown {
            continue;
        }

        let content = std::fs::read_to_string(path)?;
        files.push(SourceFile {
            path: path.to_path_buf(),
            language: lang,
            content,
        });
    }

    Ok(files)
}
