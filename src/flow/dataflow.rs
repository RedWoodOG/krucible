use std::collections::{HashMap, HashSet, VecDeque};

use super::cfg::{CfgRepo, CfgNode, CfgNodeKind, FunctionCfg, NodeId};

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
}

#[derive(Debug, Clone, Copy)]
enum Direction {
    Forward,
    Backward,
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
}
