use crate::ir::model::{
    IrCall, IrCallKind, IrFile, IrFunction, IrImport, IrLanguage, IrRepo, IrVisibility,
};
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
        "create",
        "update",
        "delete",
        "save",
        "send",
        "process",
        "handle",
        "run",
        "execute",
        "submit",
        "upload",
        "download",
        "sync",
        "load",
        "generate",
        "build",
        "fetch",
        "read",
        "write",
        "store",
        "persist",
        "validate",
        "verify",
        "authenticate",
        "authorize",
    ];
    prefixes.iter().any(|p| lower.starts_with(p))
}

fn classify_call_kind(name: &str) -> IrCallKind {
    let lower = name.to_lowercase();
    if matches_network(&lower) {
        return IrCallKind::Network;
    }
    if matches_any(
        &lower,
        &[
            "query",
            "execute",
            "insert",
            "save",
            "prisma",
            "sequelize",
            "mongoose",
            "knex",
            "sql",
            "db",
            "pool",
            "transaction",
        ],
    ) {
        return IrCallKind::Persistence;
    }
    if matches_any(&lower, &["read", "write", "open", "file", "fs", "path"]) {
        return IrCallKind::Io;
    }
    if matches_any(
        &lower,
        &[
            "verify",
            "bcrypt",
            "jwt",
            "token",
            "hash",
            "auth",
            "permission",
            "role",
            "decode",
        ],
    ) {
        return IrCallKind::Auth;
    }
    if matches_notification(&lower) {
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

/// HTTP verb tokens `get` / `put` are matched only at a left "word" boundary so identifiers like
/// `input`, `output`, `compute`, or `forget` are not classified as network via substring `put`/`get`.
fn matches_short_http_verb(name: &str, verb: &str) -> bool {
    for (i, _) in name.match_indices(verb) {
        let left_ok = i == 0
            || !name
                .as_bytes()
                .get(i - 1)
                .copied()
                .is_some_and(|b| matches!(b, b'a'..=b'z'));
        if left_ok {
            return true;
        }
    }
    false
}

fn matches_network(name: &str) -> bool {
    const LONG: &[&str] = &[
        "fetch", "axios", "request", "reqwest", "http", "post", "delete", "patch",
    ];
    matches_any(name, LONG)
        || matches_short_http_verb(name, "get")
        || matches_short_http_verb(name, "put")
}

/// Avoid matching the bare substring `ses` (e.g. in `session`); treat SES only as its own snake_case
/// segment or as the whole call name.
fn matches_notification(name: &str) -> bool {
    if matches_any(
        name,
        &[
            "mail",
            "email",
            "smtp",
            "notify",
            "sendgrid",
            "mailgun",
            "notification",
        ],
    ) {
        return true;
    }
    name == "ses" || name.split('_').any(|seg| seg == "ses")
}
