use crate::ir::model::{IrCall, IrCallKind, IrFile, IrFunction, IrImport, IrLanguage, IrRepo, IrVisibility};
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
                    is_async: function.is_async,
                    is_action_like: is_action_like_name(&function.name),
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
                    kind: classify_call_kind(&c.name),
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

fn is_action_like_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    let prefixes = [
        "create", "update", "delete", "save", "send", "process", "handle", "run", "execute",
        "submit", "upload", "download", "sync", "load", "generate", "build", "fetch", "read",
        "write", "store", "persist", "validate", "verify", "authenticate", "authorize",
    ];
    prefixes.iter().any(|p| lower.starts_with(p))
}

fn classify_call_kind(name: &str) -> IrCallKind {
    let lower = name.to_lowercase();
    if matches_any(&lower, &["fetch", "axios", "request", "reqwest", "http", "post", "get", "put", "delete", "patch"]) {
        return IrCallKind::Network;
    }
    if matches_any(&lower, &["query", "execute", "insert", "save", "prisma", "sequelize", "mongoose", "knex", "sql", "db", "pool", "transaction"]) {
        return IrCallKind::Persistence;
    }
    if matches_any(&lower, &["read", "write", "open", "file", "fs", "path"]) {
        return IrCallKind::Io;
    }
    if matches_any(&lower, &["verify", "bcrypt", "jwt", "token", "hash", "auth", "permission", "role", "decode"]) {
        return IrCallKind::Auth;
    }
    if matches_any(&lower, &["mail", "email", "smtp", "notify", "sendgrid", "mailgun", "ses", "notification"]) {
        return IrCallKind::Notification;
    }
    if lower == "then" {
        return IrCallKind::PromiseThen;
    }
    if lower == "catch" {
        return IrCallKind::PromiseCatch;
    }
    IrCallKind::Other
}

fn matches_any(name: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|p| name.contains(p))
}
