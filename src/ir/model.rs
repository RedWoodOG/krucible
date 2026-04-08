use crate::scanner::file_loader::Language;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrLanguage {
    TypeScript,
    JavaScript,
    Rust,
    Unknown,
}

impl From<&Language> for IrLanguage {
    fn from(value: &Language) -> Self {
        match value {
            Language::TypeScript => IrLanguage::TypeScript,
            Language::JavaScript => IrLanguage::JavaScript,
            Language::Rust => IrLanguage::Rust,
            Language::Unknown => IrLanguage::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrVisibility {
    Private,
    Public,
    RuntimeExposed,
}

#[derive(Debug, Clone)]
pub struct IrFunction {
    pub name: String,
    pub file: String,
    pub start_line: usize,
    pub end_line: usize,
    pub visibility: IrVisibility,
    pub attributes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct IrCall {
    pub name: String,
    pub file: String,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct IrImport {
    pub path: String,
    pub names: Vec<String>,
    pub file: String,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct IrFile {
    pub path: String,
    pub language: IrLanguage,
    pub functions: Vec<IrFunction>,
    pub calls: Vec<IrCall>,
    pub imports: Vec<IrImport>,
}

#[derive(Debug, Clone, Default)]
pub struct IrRepo {
    pub files: Vec<IrFile>,
}

impl IrRepo {
    pub fn all_functions(&self) -> impl Iterator<Item = &IrFunction> {
        self.files.iter().flat_map(|f| f.functions.iter())
    }

    pub fn all_calls(&self) -> impl Iterator<Item = &IrCall> {
        self.files.iter().flat_map(|f| f.calls.iter())
    }

    pub fn find_function(&self, file: &str, start_line: usize, name: &str) -> Option<&IrFunction> {
        self.files
            .iter()
            .find(|f| f.path == file)
            .and_then(|f| {
                f.functions
                    .iter()
                    .find(|func| func.start_line == start_line && func.name == name)
            })
    }
}
