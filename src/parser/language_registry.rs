use tree_sitter::Language;
use crate::scanner::file_loader::Language as Lang;

pub fn get_ts_language(lang: &Lang) -> Option<Language> {
    match lang {
        Lang::TypeScript => Some(tree_sitter_typescript::language_typescript()),
        Lang::JavaScript => Some(tree_sitter_typescript::language_tsx()),
        Lang::Rust => Some(tree_sitter_rust::language()),
        Lang::Unknown => None,
    }
}
