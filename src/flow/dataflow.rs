use std::collections::{HashMap, HashSet, VecDeque};

use super::cfg::{CfgRepo, CfgNode, CfgNodeKind, FunctionCfg, NodeId};
use super::predicates::FlowPredicateSet;

#[derive(Debug, Clone)]
pub struct DataflowGraph<'a> {
    cfg: &'a FunctionCfg,
    succ: HashMap<NodeId, Vec<NodeId>>,
    pred: HashMap<NodeId, Vec<NodeId>>,
}

impl<'a> DataflowGraph<'a> {
    pub fn new(cfg: &'a FunctionCfg) -> Self {
        let mut succ: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
        let mut pred: HashMap<NodeId, Vec<NodeId>> = HashMap::new();

        for edge in &cfg.edges {
            succ.entry(edge.from).or_default().push(edge.to);
            pred.entry(edge.to).or_default().push(edge.from);
        }

        Self { cfg, succ, pred }
    }

    pub fn forward_reachable_from(&self, starts: &[NodeId]) -> HashSet<NodeId> {
        self.reachable(starts, Direction::Forward)
    }

    pub fn backward_reachable_from(&self, starts: &[NodeId]) -> HashSet<NodeId> {
        self.reachable(starts, Direction::Backward)
    }

    pub fn nodes_by_name(&self, name: &str) -> Vec<&CfgNode> {
        self.cfg
            .nodes
            .iter()
            .filter(|n| matches!(&n.kind, CfgNodeKind::Call { name: n_name } if n_name == name))
            .collect()
    }

    pub fn has_path_between_names(&self, from_name: &str, to_name: &str) -> bool {
        let starts: Vec<NodeId> = self.nodes_by_name(from_name).iter().map(|n| n.id).collect();
        let targets: HashSet<NodeId> = self.nodes_by_name(to_name).iter().map(|n| n.id).collect();
        if starts.is_empty() || targets.is_empty() {
            return false;
        }
        let reachable = self.forward_reachable_from(&starts);
        reachable.iter().any(|n| targets.contains(n))
    }

    /// Query for sink call nodes that are reachable from sources without hitting any guard call.
    ///
    /// - If `source_names` is empty, function entry nodes are used as sources.
    /// - `sink_names` and `guard_names` are matched exactly against call names.
    pub fn sinks_reachable_without_guards(
        &self,
        source_names: &[&str],
        sink_names: &[&str],
        guard_names: &[&str],
    ) -> Vec<GuardedSinkHit> {
        if sink_names.is_empty() {
            return Vec::new();
        }

        let sink_set: HashSet<&str> = sink_names.iter().copied().collect();
        let guard_set: HashSet<&str> = guard_names.iter().copied().collect();
        let sink_nodes: HashSet<NodeId> = self
            .cfg
            .nodes
            .iter()
            .filter(|n| {
                matches!(
                    &n.kind,
                    CfgNodeKind::Call { name } if sink_set.contains(name.as_str())
                )
            })
            .map(|n| n.id)
            .collect();

        if sink_nodes.is_empty() {
            return Vec::new();
        }

        let guard_nodes: HashSet<NodeId> = self
            .cfg
            .nodes
            .iter()
            .filter(|n| {
                matches!(
                    &n.kind,
                    CfgNodeKind::Call { name } if guard_set.contains(name.as_str())
                )
            })
            .map(|n| n.id)
            .collect();

        let source_nodes: Vec<NodeId> = if source_names.is_empty() {
            self.cfg
                .nodes
                .iter()
                .filter(|n| matches!(n.kind, CfgNodeKind::Entry))
                .map(|n| n.id)
                .collect()
        } else {
            let source_set: HashSet<&str> = source_names.iter().copied().collect();
            self.cfg
                .nodes
                .iter()
                .filter(|n| {
                    matches!(
                        &n.kind,
                        CfgNodeKind::Call { name } if source_set.contains(name.as_str())
                    )
                })
                .map(|n| n.id)
                .collect()
        };

        let mut hits = Vec::new();
        let mut seen_sink_nodes: HashSet<NodeId> = HashSet::new();
        for source in source_nodes {
            let reachable = self.reachable_skipping_guards(source, &guard_nodes);
            for sink in &sink_nodes {
                if !reachable.contains(sink) || !seen_sink_nodes.insert(*sink) {
                    continue;
                }
                if let Some(node) = self.node_by_id(*sink) {
                    if let CfgNodeKind::Call { name } = &node.kind {
                        hits.push(GuardedSinkHit {
                            sink_name: name.clone(),
                            sink_line: node.line,
                        });
                    }
                }
            }
        }

        hits
    }

    /// Profile-driven variant of guarded-sink detection.
    /// Predicate matching is delegated to `FlowPredicateSet`.
    pub fn sinks_reachable_without_guards_by_profile(
        &self,
        source_names: &[&str],
        profile: &FlowPredicateSet,
    ) -> Vec<GuardedSinkHit> {
        let sink_nodes: HashSet<NodeId> = self
            .cfg
            .nodes
            .iter()
            .filter(|n| {
                matches!(
                    &n.kind,
                    CfgNodeKind::Call { name } if profile.is_sink(name)
                )
            })
            .map(|n| n.id)
            .collect();
        if sink_nodes.is_empty() {
            return Vec::new();
        }

        let guard_nodes: HashSet<NodeId> = self
            .cfg
            .nodes
            .iter()
            .filter(|n| {
                matches!(
                    &n.kind,
                    CfgNodeKind::Call { name } if profile.is_guard(name)
                )
            })
            .map(|n| n.id)
            .collect();

        let source_nodes: Vec<NodeId> = if source_names.is_empty() {
            self.cfg
                .nodes
                .iter()
                .filter(|n| matches!(n.kind, CfgNodeKind::Entry))
                .map(|n| n.id)
                .collect()
        } else {
            let source_set: HashSet<&str> = source_names.iter().copied().collect();
            self.cfg
                .nodes
                .iter()
                .filter(|n| {
                    matches!(
                        &n.kind,
                        CfgNodeKind::Call { name } if source_set.contains(name.as_str())
                    )
                })
                .map(|n| n.id)
                .collect()
        };

        let mut hits = Vec::new();
        let mut seen_sink_nodes: HashSet<NodeId> = HashSet::new();
        for source in source_nodes {
            let reachable = self.reachable_skipping_guards(source, &guard_nodes);
            for sink in &sink_nodes {
                if !reachable.contains(sink) || !seen_sink_nodes.insert(*sink) {
                    continue;
                }
                if let Some(node) = self.node_by_id(*sink) {
                    if let CfgNodeKind::Call { name } = &node.kind {
                        hits.push(GuardedSinkHit {
                            sink_name: name.clone(),
                            sink_line: node.line,
                        });
                    }
                }
            }
        }

        hits
    }

    fn reachable(&self, starts: &[NodeId], direction: Direction) -> HashSet<NodeId> {
        let mut visited: HashSet<NodeId> = HashSet::new();
        let mut queue: VecDeque<NodeId> = starts.iter().copied().collect();

        while let Some(node) = queue.pop_front() {
            if !visited.insert(node) {
                continue;
            }
            let neighbors = match direction {
                Direction::Forward => self.succ.get(&node),
                Direction::Backward => self.pred.get(&node),
            };
            if let Some(neighbors) = neighbors {
                for next in neighbors {
                    if !visited.contains(next) {
                        queue.push_back(*next);
                    }
                }
            }
        }

        visited
    }

    fn reachable_skipping_guards(
        &self,
        start: NodeId,
        guard_nodes: &HashSet<NodeId>,
    ) -> HashSet<NodeId> {
        let mut visited: HashSet<NodeId> = HashSet::new();
        let mut queue: VecDeque<NodeId> = VecDeque::from([start]);

        while let Some(node) = queue.pop_front() {
            if !visited.insert(node) {
                continue;
            }

            if let Some(neighbors) = self.succ.get(&node) {
                for next in neighbors {
                    if guard_nodes.contains(next) || visited.contains(next) {
                        continue;
                    }
                    queue.push_back(*next);
                }
            }
        }

        visited
    }

    fn node_by_id(&self, id: NodeId) -> Option<&CfgNode> {
        self.cfg.nodes.iter().find(|n| n.id == id)
    }
}

#[derive(Debug, Clone, Copy)]
enum Direction {
    Forward,
    Backward,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardedSinkHit {
    pub sink_name: String,
    pub sink_line: Option<usize>,
}

pub fn build_dataflow_graphs(cfg_repo: &CfgRepo) -> Vec<DataflowGraph<'_>> {
    cfg_repo.functions.iter().map(DataflowGraph::new).collect()
}

#[cfg(test)]
mod tests {
    use crate::flow::cfg::build_cfg_repo;
    use crate::ir::model::{
        IrCall, IrCallKind, IrFile, IrFunction, IrLanguage, IrRepo, IrVisibility,
    };

    use super::DataflowGraph;

    fn sample_cfg() -> crate::flow::cfg::FunctionCfg {
        let repo = IrRepo {
            files: vec![IrFile {
                path: "x.ts".into(),
                language: IrLanguage::TypeScript,
                functions: vec![IrFunction {
                    name: "work".into(),
                    file: "x.ts".into(),
                    start_line: 10,
                    end_line: 30,
                    visibility: IrVisibility::Private,
                    is_async: true,
                    is_action_like: true,
                    attributes: vec![],
                }],
                calls: vec![
                    IrCall {
                        name: "then".into(),
                        file: "x.ts".into(),
                        line: 12,
                        kind: IrCallKind::PromiseThen,
                    },
                    IrCall {
                        name: "catch".into(),
                        file: "x.ts".into(),
                        line: 20,
                        kind: IrCallKind::PromiseCatch,
                    },
                ],
                imports: vec![],
            }],
        };

        build_cfg_repo(&repo).functions.into_iter().next().unwrap()
    }

    #[test]
    fn finds_forward_path_between_call_names() {
        let cfg = sample_cfg();
        let df = DataflowGraph::new(&cfg);
        assert!(df.has_path_between_names("then", "catch"));
    }

    #[test]
    fn forward_and_backward_reachability_are_non_empty() {
        let cfg = sample_cfg();
        let df = DataflowGraph::new(&cfg);
        let then_nodes = df.nodes_by_name("then");
        let start = vec![then_nodes[0].id];
        let fwd = df.forward_reachable_from(&start);
        let back = df.backward_reachable_from(&start);
        assert!(!fwd.is_empty());
        assert!(!back.is_empty());
    }

    #[test]
    fn detects_sink_reachable_without_guard() {
        let cfg = sample_cfg();
        let df = DataflowGraph::new(&cfg);
        let hits = df.sinks_reachable_without_guards(&["then"], &["catch"], &["validate"]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].sink_name, "catch");
    }

    #[test]
    fn skips_sink_when_guard_blocks_path() {
        let repo = IrRepo {
            files: vec![IrFile {
                path: "x.ts".into(),
                language: IrLanguage::TypeScript,
                functions: vec![IrFunction {
                    name: "work".into(),
                    file: "x.ts".into(),
                    start_line: 10,
                    end_line: 30,
                    visibility: IrVisibility::Private,
                    is_async: true,
                    is_action_like: true,
                    attributes: vec![],
                }],
                calls: vec![
                    IrCall {
                        name: "input".into(),
                        file: "x.ts".into(),
                        line: 11,
                        kind: IrCallKind::Other,
                    },
                    IrCall {
                        name: "validate".into(),
                        file: "x.ts".into(),
                        line: 12,
                        kind: IrCallKind::Auth,
                    },
                    IrCall {
                        name: "execute".into(),
                        file: "x.ts".into(),
                        line: 13,
                        kind: IrCallKind::Persistence,
                    },
                ],
                imports: vec![],
            }],
        };

        let cfg = build_cfg_repo(&repo).functions.into_iter().next().unwrap();
        let df = DataflowGraph::new(&cfg);
        let hits = df.sinks_reachable_without_guards(&["input"], &["execute"], &["validate"]);
        assert!(hits.is_empty());
    }
}
