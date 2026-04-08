use crate::ir::model::{IrCall, IrFile, IrFunction, IrImport, IrLanguage, IrRepo, IrVisibility};
use crate::parser::tree_sitter::{FunctionKind, ParsedFile};

pub fn from_parsed_files(parsed_files: &[ParsedFile]) -> IrRepo {
    let files = parsed_files
        .iter()
        .map(|file| IrFile {
            path: file.file.clone(),
            language: IrLanguage::from(&file.language),
            functions: file
                .functions
                .iter()
                .map(|function| IrFunction {
                    name: function.name.clone(),
                    file: function.file.clone(),
                    start_line: function.line,
                    end_line: function.end_line,
                    visibility: match function.kind {
                        FunctionKind::Plain => IrVisibility::Private,
                        FunctionKind::Public => IrVisibility::Public,
                        FunctionKind::TauriCommand => IrVisibility::RuntimeExposed,
                    },
                    attributes: function.attributes.clone(),
                })
                .collect(),
            calls: file
                .calls
                .iter()
                .map(|c| IrCall {
                    name: c.name.clone(),
                    file: c.file.clone(),
                    line: c.line,
                })
                .collect(),
            imports: file
                .imports
                .iter()
                .map(|i| IrImport {
                    path: i.path.clone(),
                    names: i.names.clone(),
                    file: i.file.clone(),
                    line: i.line,
                })
                .collect(),
        })
        .collect();

    IrRepo { files }
}
