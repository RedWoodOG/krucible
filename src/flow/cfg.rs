use crate::ir::model::IrRepo;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub usize);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfgNodeKind {
    Entry,
    Exit,
    Call { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgNode {
    pub id: NodeId,
    pub kind: CfgNodeKind,
    pub line: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfgEdgeKind {
    Normal,
    TrueBranch,
    FalseBranch,
    LoopBack,
    Exceptional,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgEdge {
    pub from: NodeId,
    pub to: NodeId,
    pub kind: CfgEdgeKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionCfg {
    pub function_name: String,
    pub file: String,
    pub start_line: usize,
    pub end_line: usize,
    pub nodes: Vec<CfgNode>,
    pub edges: Vec<CfgEdge>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CfgRepo {
    pub functions: Vec<FunctionCfg>,
}

pub fn build_cfg_repo(ir_repo: &IrRepo) -> CfgRepo {
    let mut functions = Vec::new();

    for function in ir_repo.all_functions() {
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        let mut next_id: usize = 0;

        let entry_id = NodeId(next_id);
        next_id += 1;
        nodes.push(CfgNode {
            id: entry_id,
            kind: CfgNodeKind::Entry,
            line: Some(function.start_line),
        });

        let mut call_sites: Vec<_> = ir_repo
            .calls_in_function(function)
            .map(|c| (c.line, c.name.clone()))
            .collect();
        call_sites.sort_by_key(|(line, _)| *line);

        let mut previous = entry_id;
        for (line, name) in call_sites {
            let id = NodeId(next_id);
            next_id += 1;
            nodes.push(CfgNode {
                id,
                kind: CfgNodeKind::Call { name },
                line: Some(line),
            });
            edges.push(CfgEdge {
                from: previous,
                to: id,
                kind: CfgEdgeKind::Normal,
            });
            previous = id;
        }

        let exit_id = NodeId(next_id);
        nodes.push(CfgNode {
            id: exit_id,
            kind: CfgNodeKind::Exit,
            line: Some(function.end_line),
        });
        edges.push(CfgEdge {
            from: previous,
            to: exit_id,
            kind: CfgEdgeKind::Normal,
        });

        functions.push(FunctionCfg {
            function_name: function.name.clone(),
            file: function.file.clone(),
            start_line: function.start_line,
            end_line: function.end_line,
            nodes,
            edges,
        });
    }

    CfgRepo { functions }
}

#[cfg(test)]
mod tests {
    use crate::ir::model::{
        IrCall, IrCallKind, IrFile, IrFunction, IrLanguage, IrRepo, IrVisibility,
    };

    use super::{build_cfg_repo, CfgNodeKind};

    #[test]
    fn builds_linear_cfg_for_function_calls() {
        let repo = IrRepo {
            files: vec![IrFile {
                path: "a.ts".into(),
                language: IrLanguage::TypeScript,
                functions: vec![IrFunction {
                    name: "processOrder".into(),
                    file: "a.ts".into(),
                    start_line: 10,
                    end_line: 20,
                    visibility: IrVisibility::Private,
                    is_async: true,
                    is_action_like: true,
                    attributes: vec![],
                }],
                calls: vec![
                    IrCall {
                        name: "save".into(),
                        file: "a.ts".into(),
                        line: 12,
                        kind: IrCallKind::Persistence,
                    },
                    IrCall {
                        name: "notify".into(),
                        file: "a.ts".into(),
                        line: 18,
                        kind: IrCallKind::Notification,
                    },
                ],
                imports: vec![],
            }],
        };

        let cfg = build_cfg_repo(&repo);
        assert_eq!(cfg.functions.len(), 1);
        let f = &cfg.functions[0];
        assert_eq!(f.nodes.len(), 4);
        assert_eq!(f.edges.len(), 3);
        assert!(matches!(f.nodes[0].kind, CfgNodeKind::Entry));
        assert!(matches!(f.nodes[1].kind, CfgNodeKind::Call { .. }));
        assert!(matches!(f.nodes[2].kind, CfgNodeKind::Call { .. }));
        assert!(matches!(f.nodes[3].kind, CfgNodeKind::Exit));
    }

    #[test]
    fn builds_entry_exit_only_for_empty_function_body() {
        let repo = IrRepo {
            files: vec![IrFile {
                path: "a.rs".into(),
                language: IrLanguage::Rust,
                functions: vec![IrFunction {
                    name: "helper".into(),
                    file: "a.rs".into(),
                    start_line: 1,
                    end_line: 3,
                    visibility: IrVisibility::Private,
                    is_async: false,
                    is_action_like: false,
                    attributes: vec![],
                }],
                calls: vec![],
                imports: vec![],
            }],
        };

        let cfg = build_cfg_repo(&repo);
        assert_eq!(cfg.functions.len(), 1);
        let f = &cfg.functions[0];
        assert_eq!(f.nodes.len(), 2);
        assert_eq!(f.edges.len(), 1);
        assert!(matches!(f.nodes[0].kind, CfgNodeKind::Entry));
        assert!(matches!(f.nodes[1].kind, CfgNodeKind::Exit));
        assert_eq!(f.edges[0].from, f.nodes[0].id);
        assert_eq!(f.edges[0].to, f.nodes[1].id);
    }

    #[test]
    fn sorts_call_nodes_by_line() {
        let repo = IrRepo {
            files: vec![IrFile {
                path: "b.ts".into(),
                language: IrLanguage::TypeScript,
                functions: vec![IrFunction {
                    name: "run".into(),
                    file: "b.ts".into(),
                    start_line: 5,
                    end_line: 25,
                    visibility: IrVisibility::Private,
                    is_async: false,
                    is_action_like: true,
                    attributes: vec![],
                }],
                calls: vec![
                    IrCall {
                        name: "second".into(),
                        file: "b.ts".into(),
                        line: 20,
                        kind: IrCallKind::Other,
                    },
                    IrCall {
                        name: "first".into(),
                        file: "b.ts".into(),
                        line: 8,
                        kind: IrCallKind::Other,
                    },
                ],
                imports: vec![],
            }],
        };

        let cfg = build_cfg_repo(&repo);
        let f = &cfg.functions[0];
        match &f.nodes[1].kind {
            CfgNodeKind::Call { name } => assert_eq!(name, "first"),
            _ => panic!("expected first call node"),
        }
        match &f.nodes[2].kind {
            CfgNodeKind::Call { name } => assert_eq!(name, "second"),
            _ => panic!("expected second call node"),
        }
    }
}
