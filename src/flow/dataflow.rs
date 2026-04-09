use std::collections::{HashMap, HashSet, VecDeque};

use super::cfg::{CfgNode, CfgNodeKind, CfgRepo, FunctionCfg, NodeId};
use super::predicates::{FlowPredicateSet, SanitizerStrength, TAINT_TAG_ANY};
use crate::ir::symbols::{ResolutionConfidence, SymbolTable};

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
            self.cfg
                .nodes
                .iter()
                .filter(|n| {
                    match &n.kind {
                        CfgNodeKind::Call { name } => {
                            source_names.iter().any(|source| {
                                let source = source.to_lowercase();
                                name.to_lowercase().contains(source.as_str())
                            }) || profile.is_source(name)
                        }
                        _ => false,
                    }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterproceduralGuardedSinkHit {
    pub sink_name: String,
    pub sink_line: Option<usize>,
    pub sink_file: String,
    pub sink_function: String,
    pub call_depth: usize,
    pub taint_tags: Vec<String>,
    pub sink_tags: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct CallTargetIndex {
    by_call_site: HashMap<(String, usize), Vec<usize>>,
}

impl CallTargetIndex {
    pub fn from_symbol_table(
        cfg_repo: &CfgRepo,
        symbols: &SymbolTable,
        min_confidence: ResolutionConfidence,
    ) -> Self {
        let function_idx_by_location: HashMap<(String, usize), usize> = cfg_repo
            .functions
            .iter()
            .enumerate()
            .map(|(idx, function)| ((function.file.clone(), function.start_line), idx))
            .collect();

        let mut by_call_site: HashMap<(String, usize), Vec<usize>> = HashMap::new();
        for resolved in symbols
            .resolved_calls()
            .iter()
            .filter(|resolved| resolved.confidence >= min_confidence)
        {
            let Some(target_idx) = function_idx_by_location
                .get(&(resolved.target_file.clone(), resolved.target_line))
            else {
                continue;
            };
            by_call_site
                .entry((resolved.call_file.clone(), resolved.call_line))
                .or_default()
                .push(*target_idx);
        }

        for targets in by_call_site.values_mut() {
            targets.sort_unstable();
            targets.dedup();
        }

        Self { by_call_site }
    }

    pub fn targets_for_callsite(&self, call_file: &str, call_line: usize) -> Option<&[usize]> {
        self.by_call_site
            .get(&(call_file.to_string(), call_line))
            .map(Vec::as_slice)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TaintTags {
    values: Vec<String>,
}

impl TaintTags {
    fn any() -> Self {
        Self {
            values: vec![TAINT_TAG_ANY.to_string()],
        }
    }

    fn intersects(&self, tags: &[String]) -> bool {
        tags_intersect(&self.values, tags)
    }

    fn apply_strong_sanitizer(&self, sanitizer_tags: &[String]) -> Option<Self> {
        if sanitizer_tags.is_empty() {
            return Some(self.clone());
        }
        if contains_any_tag(sanitizer_tags) {
            if contains_any_tag(&self.values) {
                return None;
            }
            return None;
        }
        if contains_any_tag(&self.values) {
            // Unknown/any taint cannot be proven clean by tag-specific sanitizers.
            return Some(self.clone());
        }

        let cleaned: Vec<String> = self
            .values
            .iter()
            .filter(|tag| !sanitizer_tags.contains(tag))
            .cloned()
            .collect();
        if cleaned.is_empty() {
            None
        } else {
            Some(Self { values: cleaned })
        }
    }

    fn as_slice(&self) -> &[String] {
        &self.values
    }
}

pub fn build_dataflow_graphs(cfg_repo: &CfgRepo) -> Vec<DataflowGraph<'_>> {
    cfg_repo.functions.iter().map(DataflowGraph::new).collect()
}

pub fn sinks_reachable_without_guards_interprocedural(
    cfg_repo: &CfgRepo,
    start_function: &FunctionCfg,
    source_names: &[&str],
    profile: &FlowPredicateSet,
    max_call_depth: usize,
    call_targets: Option<&CallTargetIndex>,
) -> Vec<InterproceduralGuardedSinkHit> {
    let Some(start_idx) = cfg_repo.functions.iter().position(|function| {
        function.file == start_function.file
            && function.function_name == start_function.function_name
            && function.start_line == start_function.start_line
    }) else {
        return Vec::new();
    };

    let function_by_name: HashMap<String, Vec<usize>> = cfg_repo
        .functions
        .iter()
        .enumerate()
        .fold(HashMap::new(), |mut acc, (idx, function)| {
            acc.entry(function.function_name.clone())
                .or_default()
                .push(idx);
            acc
        });

    let successors: Vec<HashMap<NodeId, Vec<NodeId>>> = cfg_repo
        .functions
        .iter()
        .map(|function| {
            let mut succ: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
            for edge in &function.edges {
                succ.entry(edge.from).or_default().push(edge.to);
            }
            succ
        })
        .collect();

    let start_nodes: Vec<(NodeId, TaintTags)> = if source_names.is_empty() {
        cfg_repo.functions[start_idx]
            .nodes
            .iter()
            .filter(|n| matches!(n.kind, CfgNodeKind::Entry))
            .map(|n| (n.id, TaintTags::any()))
            .collect()
    } else {
        cfg_repo.functions[start_idx]
            .nodes
            .iter()
            .filter_map(|n| match &n.kind {
                CfgNodeKind::Call { name } => {
                    let mut tags = profile.source_tags_for_call(name);
                    if tags.is_empty() && match_any_substr_name(source_names, name) {
                        tags.push(TAINT_TAG_ANY.to_string());
                    }
                    let tags = normalize_taint_tags(tags);
                    if tags.is_empty() {
                        return None;
                    }
                    let taint_tags = TaintTags { values: tags };
                    Some((n.id, taint_tags))
                }
                _ => None,
            })
            .collect()
    };

    if start_nodes.is_empty() {
        return Vec::new();
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct TraversalState {
        function_idx: usize,
        node_id: NodeId,
        depth: usize,
        taint_tags: TaintTags,
    }

    let mut queue: VecDeque<TraversalState> = start_nodes
        .into_iter()
        .map(|(node_id, taint_tags)| TraversalState {
            function_idx: start_idx,
            node_id,
            depth: 0,
            taint_tags,
        })
        .collect();
    let mut visited: HashSet<TraversalState> = HashSet::new();
    let mut hits = Vec::new();
    let mut seen_sinks: HashSet<(usize, NodeId)> = HashSet::new();

    while let Some(state) = queue.pop_front() {
        if !visited.insert(state.clone()) {
            continue;
        }

        let function = &cfg_repo.functions[state.function_idx];
        let Some(node) = function.nodes.iter().find(|n| n.id == state.node_id) else {
            continue;
        };

        let mut effective_tags = state.taint_tags.clone();
        if let CfgNodeKind::Call { name } = &node.kind {
            if profile.is_guard(name) {
                continue;
            }

            if let Some((strength, sanitizer_tags)) =
                best_sanitizer_effect(profile, name, &effective_tags)
            {
                if strength == SanitizerStrength::Strong {
                    let Some(cleaned) = effective_tags.apply_strong_sanitizer(&sanitizer_tags)
                    else {
                        continue;
                    };
                    effective_tags = cleaned;
                }
            }

            let sink_tags = profile.sink_tags_for_call(name);
            if !sink_tags.is_empty()
                && effective_tags.intersects(&sink_tags)
                && seen_sinks.insert((state.function_idx, state.node_id))
            {
                hits.push(InterproceduralGuardedSinkHit {
                    sink_name: name.clone(),
                    sink_line: node.line,
                    sink_file: function.file.clone(),
                    sink_function: function.function_name.clone(),
                    call_depth: state.depth,
                    taint_tags: effective_tags.as_slice().to_vec(),
                    sink_tags: intersect_taint_tags(effective_tags.as_slice(), &sink_tags),
                });
            }

            if state.depth < max_call_depth {
                let resolved_callees: Vec<usize> = if let (Some(index), Some(call_line)) =
                    (call_targets, node.line)
                {
                    index
                        .targets_for_callsite(function.file.as_str(), call_line)
                        .map(|targets| targets.to_vec())
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };

                let callee_indices: Vec<usize> = if call_targets.is_some() {
                    resolved_callees
                } else {
                    function_by_name.get(name).cloned().unwrap_or_default()
                };

                for callee_idx in callee_indices {
                    if let Some(entry_node) = cfg_repo.functions[callee_idx]
                        .nodes
                        .iter()
                        .find(|n| matches!(n.kind, CfgNodeKind::Entry))
                    {
                        queue.push_back(TraversalState {
                            function_idx: callee_idx,
                            node_id: entry_node.id,
                            depth: state.depth + 1,
                            taint_tags: effective_tags.clone(),
                        });
                    }
                }
            }
        }

        if let Some(next_nodes) = successors[state.function_idx].get(&state.node_id) {
            for next in next_nodes {
                let blocked = cfg_repo.functions[state.function_idx]
                    .nodes
                    .iter()
                    .find(|n| n.id == *next)
                    .and_then(|n| {
                        if let CfgNodeKind::Call { name } = &n.kind {
                            Some(profile.is_guard(name))
                        } else {
                            None
                        }
                    })
                    .unwrap_or(false);
                if blocked {
                    continue;
                }
                queue.push_back(TraversalState {
                    function_idx: state.function_idx,
                    node_id: *next,
                    depth: state.depth,
                    taint_tags: effective_tags.clone(),
                });
            }
        }
    }

    hits
}

fn best_sanitizer_effect(
    profile: &FlowPredicateSet,
    call_name: &str,
    taint_tags: &TaintTags,
) -> Option<(SanitizerStrength, Vec<String>)> {
    let mut best_strength: Option<SanitizerStrength> = None;
    let mut best_tags: Vec<String> = Vec::new();

    for sanitizer in profile.matching_sanitizers_for_call(call_name) {
        if !taint_tags.intersects(&sanitizer.tags) {
            continue;
        }
        match best_strength {
            None => {
                best_strength = Some(sanitizer.strength);
                best_tags = sanitizer.tags.clone();
            }
            Some(existing) if sanitizer.strength > existing => {
                best_strength = Some(sanitizer.strength);
                best_tags = sanitizer.tags.clone();
            }
            Some(existing) if sanitizer.strength == existing => {
                best_tags.extend(sanitizer.tags.clone());
                best_tags = normalize_taint_tags(best_tags);
            }
            _ => {}
        }
    }

    best_strength.map(|strength| (strength, normalize_taint_tags(best_tags)))
}

fn normalize_taint_tags(values: Vec<String>) -> Vec<String> {
    let mut tags: Vec<String> = values
        .into_iter()
        .map(|tag| tag.trim().to_lowercase())
        .filter(|tag| !tag.is_empty())
        .collect();
    tags.sort();
    tags.dedup();
    tags
}

fn contains_any_tag(tags: &[String]) -> bool {
    tags.iter().any(|tag| tag == TAINT_TAG_ANY)
}

fn tags_intersect(left: &[String], right: &[String]) -> bool {
    if left.is_empty() || right.is_empty() {
        return false;
    }
    if contains_any_tag(left) || contains_any_tag(right) {
        return true;
    }
    left.iter().any(|tag| right.contains(tag))
}

fn intersect_taint_tags(left: &[String], right: &[String]) -> Vec<String> {
    if left.is_empty() || right.is_empty() {
        return Vec::new();
    }
    if contains_any_tag(left) && contains_any_tag(right) {
        return vec![TAINT_TAG_ANY.to_string()];
    }
    if contains_any_tag(left) {
        return normalize_taint_tags(right.to_vec());
    }
    if contains_any_tag(right) {
        return normalize_taint_tags(left.to_vec());
    }
    normalize_taint_tags(
        left.iter()
            .filter(|tag| right.contains(tag))
            .cloned()
            .collect(),
    )
}

fn match_any_substr_name(patterns: &[&str], value: &str) -> bool {
    let value = value.to_lowercase();
    patterns
        .iter()
        .any(|pattern| value.contains(pattern.to_lowercase().as_str()))
}

#[cfg(test)]
mod tests {
    use crate::flow::cfg::build_cfg_repo;
    use crate::flow::predicates::{parse_model_json, FlowPredicateSet};
    use crate::ir::model::{
        IrCall, IrCallKind, IrFile, IrFunction, IrLanguage, IrRepo, IrVisibility,
    };
    use crate::ir::symbols::{ResolutionConfidence, SymbolTable};

    use super::{sinks_reachable_without_guards_interprocedural, CallTargetIndex, DataflowGraph};

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

    fn interprocedural_repo(include_guard_in_callee: bool) -> IrRepo {
        let mut calls = vec![
            IrCall {
                name: "persistOrder".into(),
                file: "x.ts".into(),
                line: 5,
                kind: IrCallKind::Other,
            },
            IrCall {
                name: "execute".into(),
                file: "x.ts".into(),
                line: 35,
                kind: IrCallKind::Persistence,
            },
        ];
        if include_guard_in_callee {
            calls.push(IrCall {
                name: "validate".into(),
                file: "x.ts".into(),
                line: 34,
                kind: IrCallKind::Auth,
            });
        }

        IrRepo {
            files: vec![IrFile {
                path: "x.ts".into(),
                language: IrLanguage::TypeScript,
                functions: vec![
                    IrFunction {
                        name: "adminCheckout".into(),
                        file: "x.ts".into(),
                        start_line: 1,
                        end_line: 20,
                        visibility: IrVisibility::Private,
                        is_async: true,
                        is_action_like: true,
                        attributes: vec![],
                    },
                    IrFunction {
                        name: "persistOrder".into(),
                        file: "x.ts".into(),
                        start_line: 30,
                        end_line: 40,
                        visibility: IrVisibility::Private,
                        is_async: true,
                        is_action_like: true,
                        attributes: vec![],
                    },
                ],
                calls,
                imports: vec![],
            }],
        }
    }

    fn typed_policy_with_sanitizer(strength: &str) -> FlowPredicateSet {
        let raw = format!(
            r#"
            {{
              "profiles": {{
                "typed": {{
                  "source_models": [{{ "pattern": "request", "tags": ["pii"] }}],
                  "sink_models": [{{ "pattern": "execute", "tags": ["pii"] }}],
                  "sanitizer_models": [
                    {{ "pattern": "mask", "tags": ["pii"], "strength": "{strength}" }}
                  ],
                  "sensitive_functions": ["admin"]
                }}
              }}
            }}"#
        );
        let file = parse_model_json(&raw).expect("typed model should parse");
        let profile = file.profiles.get("typed").expect("typed profile should exist");
        FlowPredicateSet::from_model("typed".into(), profile.clone())
    }

    #[test]
    fn interprocedural_query_reaches_sink_in_callee() {
        let repo = interprocedural_repo(false);
        let cfg_repo = build_cfg_repo(&repo);
        let start = cfg_repo
            .functions
            .iter()
            .find(|f| f.function_name == "adminCheckout")
            .expect("start function should exist");
        let hits = sinks_reachable_without_guards_interprocedural(
            &cfg_repo,
            start,
            &[],
            &FlowPredicateSet::generic_security(),
            2,
            None,
        );
        assert!(hits
            .iter()
            .any(|h| h.sink_name == "execute" && h.sink_function == "persistOrder"));
    }

    #[test]
    fn interprocedural_query_respects_call_depth_limit() {
        let repo = interprocedural_repo(false);
        let cfg_repo = build_cfg_repo(&repo);
        let start = cfg_repo
            .functions
            .iter()
            .find(|f| f.function_name == "adminCheckout")
            .expect("start function should exist");
        let hits = sinks_reachable_without_guards_interprocedural(
            &cfg_repo,
            start,
            &[],
            &FlowPredicateSet::generic_security(),
            0,
            None,
        );
        assert!(hits.is_empty());
    }

    #[test]
    fn interprocedural_query_stops_on_callee_guard() {
        let repo = interprocedural_repo(true);
        let cfg_repo = build_cfg_repo(&repo);
        let start = cfg_repo
            .functions
            .iter()
            .find(|f| f.function_name == "adminCheckout")
            .expect("start function should exist");
        let hits = sinks_reachable_without_guards_interprocedural(
            &cfg_repo,
            start,
            &[],
            &FlowPredicateSet::generic_security(),
            2,
            None,
        );
        assert!(hits.is_empty());
    }

    #[test]
    fn interprocedural_query_uses_symbol_targets_to_reduce_ambiguity() {
        let repo = IrRepo {
            files: vec![
                IrFile {
                    path: "entry.ts".into(),
                    language: IrLanguage::TypeScript,
                    functions: vec![IrFunction {
                        name: "adminCheckout".into(),
                        file: "entry.ts".into(),
                        start_line: 1,
                        end_line: 20,
                        visibility: IrVisibility::Private,
                        is_async: true,
                        is_action_like: true,
                        attributes: vec![],
                    }],
                    calls: vec![IrCall {
                        name: "persistOrder".into(),
                        file: "entry.ts".into(),
                        line: 5,
                        kind: IrCallKind::Other,
                    }],
                    imports: vec![],
                },
                IrFile {
                    path: "trusted.ts".into(),
                    language: IrLanguage::TypeScript,
                    functions: vec![IrFunction {
                        name: "persistOrder".into(),
                        file: "trusted.ts".into(),
                        start_line: 30,
                        end_line: 40,
                        visibility: IrVisibility::Public,
                        is_async: true,
                        is_action_like: true,
                        attributes: vec![],
                    }],
                    calls: vec![
                        IrCall {
                            name: "validate".into(),
                            file: "trusted.ts".into(),
                            line: 31,
                            kind: IrCallKind::Auth,
                        },
                        IrCall {
                            name: "execute".into(),
                            file: "trusted.ts".into(),
                            line: 33,
                            kind: IrCallKind::Persistence,
                        },
                    ],
                    imports: vec![],
                },
                IrFile {
                    path: "legacy.ts".into(),
                    language: IrLanguage::TypeScript,
                    functions: vec![IrFunction {
                        name: "persistOrder".into(),
                        file: "legacy.ts".into(),
                        start_line: 50,
                        end_line: 60,
                        visibility: IrVisibility::Private,
                        is_async: true,
                        is_action_like: true,
                        attributes: vec![],
                    }],
                    calls: vec![IrCall {
                        name: "execute".into(),
                        file: "legacy.ts".into(),
                        line: 53,
                        kind: IrCallKind::Persistence,
                    }],
                    imports: vec![],
                },
            ],
        };

        let cfg_repo = build_cfg_repo(&repo);
        let start = cfg_repo
            .functions
            .iter()
            .find(|f| f.function_name == "adminCheckout")
            .expect("start function should exist");
        let symbol_table = SymbolTable::from_repo(&repo);
        let call_targets = CallTargetIndex::from_symbol_table(
            &cfg_repo,
            &symbol_table,
            ResolutionConfidence::Medium,
        );

        let hits = sinks_reachable_without_guards_interprocedural(
            &cfg_repo,
            start,
            &[],
            &FlowPredicateSet::generic_security(),
            2,
            Some(&call_targets),
        );
        assert!(hits.is_empty());
    }

    #[test]
    fn typed_tags_require_source_sink_compatibility() {
        let raw = r#"
        {
          "profiles": {
            "typed": {
              "source_models": [{ "pattern": "request", "tags": ["pii"] }],
              "sink_models": [{ "pattern": "execute", "tags": ["payment"] }],
              "sensitive_functions": ["admin"]
            }
          }
        }"#;
        let file = parse_model_json(raw).expect("typed model should parse");
        let profile = file.profiles.get("typed").expect("typed profile should exist");
        let policy = FlowPredicateSet::from_model("typed".into(), profile.clone());

        let repo = IrRepo {
            files: vec![IrFile {
                path: "typed.ts".into(),
                language: IrLanguage::TypeScript,
                functions: vec![IrFunction {
                    name: "adminCheckout".into(),
                    file: "typed.ts".into(),
                    start_line: 1,
                    end_line: 20,
                    visibility: IrVisibility::Private,
                    is_async: true,
                    is_action_like: true,
                    attributes: vec![],
                }],
                calls: vec![
                    IrCall {
                        name: "requestBody".into(),
                        file: "typed.ts".into(),
                        line: 2,
                        kind: IrCallKind::Other,
                    },
                    IrCall {
                        name: "execute".into(),
                        file: "typed.ts".into(),
                        line: 3,
                        kind: IrCallKind::Persistence,
                    },
                ],
                imports: vec![],
            }],
        };

        let cfg_repo = build_cfg_repo(&repo);
        let start = &cfg_repo.functions[0];
        let hits =
            sinks_reachable_without_guards_interprocedural(&cfg_repo, start, &["request"], &policy, 1, None);
        assert!(hits.is_empty());
    }

    #[test]
    fn strong_sanitizer_cleans_matching_taint_tags() {
        let policy = typed_policy_with_sanitizer("strong");
        let repo = IrRepo {
            files: vec![IrFile {
                path: "typed.ts".into(),
                language: IrLanguage::TypeScript,
                functions: vec![IrFunction {
                    name: "adminCheckout".into(),
                    file: "typed.ts".into(),
                    start_line: 1,
                    end_line: 20,
                    visibility: IrVisibility::Private,
                    is_async: true,
                    is_action_like: true,
                    attributes: vec![],
                }],
                calls: vec![
                    IrCall {
                        name: "requestBody".into(),
                        file: "typed.ts".into(),
                        line: 2,
                        kind: IrCallKind::Other,
                    },
                    IrCall {
                        name: "maskPii".into(),
                        file: "typed.ts".into(),
                        line: 3,
                        kind: IrCallKind::Other,
                    },
                    IrCall {
                        name: "execute".into(),
                        file: "typed.ts".into(),
                        line: 4,
                        kind: IrCallKind::Persistence,
                    },
                ],
                imports: vec![],
            }],
        };

        let cfg_repo = build_cfg_repo(&repo);
        let start = &cfg_repo.functions[0];
        let hits =
            sinks_reachable_without_guards_interprocedural(&cfg_repo, start, &["request"], &policy, 1, None);
        assert!(hits.is_empty());
    }

    #[test]
    fn weak_sanitizer_does_not_clean_matching_taint_tags() {
        let policy = typed_policy_with_sanitizer("weak");
        let repo = IrRepo {
            files: vec![IrFile {
                path: "typed.ts".into(),
                language: IrLanguage::TypeScript,
                functions: vec![IrFunction {
                    name: "adminCheckout".into(),
                    file: "typed.ts".into(),
                    start_line: 1,
                    end_line: 20,
                    visibility: IrVisibility::Private,
                    is_async: true,
                    is_action_like: true,
                    attributes: vec![],
                }],
                calls: vec![
                    IrCall {
                        name: "requestBody".into(),
                        file: "typed.ts".into(),
                        line: 2,
                        kind: IrCallKind::Other,
                    },
                    IrCall {
                        name: "maskPii".into(),
                        file: "typed.ts".into(),
                        line: 3,
                        kind: IrCallKind::Other,
                    },
                    IrCall {
                        name: "execute".into(),
                        file: "typed.ts".into(),
                        line: 4,
                        kind: IrCallKind::Persistence,
                    },
                ],
                imports: vec![],
            }],
        };

        let cfg_repo = build_cfg_repo(&repo);
        let start = &cfg_repo.functions[0];
        let hits =
            sinks_reachable_without_guards_interprocedural(&cfg_repo, start, &["request"], &policy, 1, None);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].sink_name, "execute");
        assert!(hits[0].taint_tags.contains(&"pii".to_string()));
        assert!(hits[0].sink_tags.contains(&"pii".to_string()));
    }
}
