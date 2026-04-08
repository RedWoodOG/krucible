use std::collections::HashMap;

use crate::ir::model::{IrRepo, IrVisibility};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResolutionConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCall {
    pub call_file: String,
    pub call_line: usize,
    pub target_file: String,
    pub target_line: usize,
    pub confidence: ResolutionConfidence,
}

#[derive(Debug, Clone, Default)]
pub struct SymbolTable {
    defs_by_name: HashMap<String, Vec<FunctionSymbol>>,
    resolved_calls: Vec<ResolvedCall>,
}

#[derive(Debug, Clone)]
struct FunctionSymbol {
    file: String,
    line: usize,
    visibility: IrVisibility,
}

impl SymbolTable {
    pub fn from_repo(repo: &IrRepo) -> Self {
        let mut defs_by_name: HashMap<String, Vec<FunctionSymbol>> = HashMap::new();

        for function in repo.all_functions() {
            defs_by_name
                .entry(function.name.clone())
                .or_default()
                .push(FunctionSymbol {
                    file: function.file.clone(),
                    line: function.start_line,
                    visibility: function.visibility.clone(),
                });
        }

        let mut resolved_calls = Vec::new();
        for call in repo.all_calls() {
            let Some(candidates) = defs_by_name.get(&call.name) else {
                continue;
            };

            // Resolve against all candidates and keep best confidence only.
            let mut best_conf = ResolutionConfidence::Low;
            let mut best_targets: Vec<&FunctionSymbol> = Vec::new();

            for candidate in candidates {
                let conf = if candidate.file == call.file {
                    ResolutionConfidence::High
                } else if matches!(
                    candidate.visibility,
                    IrVisibility::Public | IrVisibility::RuntimeExposed
                ) {
                    ResolutionConfidence::Medium
                } else {
                    ResolutionConfidence::Low
                };

                match conf.cmp(&best_conf) {
                    std::cmp::Ordering::Greater => {
                        best_conf = conf;
                        best_targets.clear();
                        best_targets.push(candidate);
                    }
                    std::cmp::Ordering::Equal => {
                        best_targets.push(candidate);
                    }
                    std::cmp::Ordering::Less => {}
                }
            }

            for target in best_targets {
                resolved_calls.push(ResolvedCall {
                    call_file: call.file.clone(),
                    call_line: call.line,
                    target_file: target.file.clone(),
                    target_line: target.line,
                    confidence: best_conf,
                });
            }
        }

        Self {
            defs_by_name,
            resolved_calls,
        }
    }

    pub fn has_confident_reference(
        &self,
        name: &str,
        file: &str,
        line: usize,
        min_confidence: ResolutionConfidence,
    ) -> bool {
        self.resolved_calls.iter().any(|resolved| {
            resolved.target_file == file
                && resolved.target_line == line
                && resolved.confidence >= min_confidence
                && self
                    .defs_by_name
                    .get(name)
                    .map(|defs| defs.iter().any(|d| d.file == file && d.line == line))
                    .unwrap_or(false)
        })
    }

    pub fn resolved_call_targets_for(
        &self,
        name: &str,
        min_confidence: ResolutionConfidence,
    ) -> Vec<(String, usize)> {
        let mut out = Vec::new();
        for resolved in &self.resolved_calls {
            if resolved.confidence < min_confidence {
                continue;
            }
            if let Some(defs) = self.defs_by_name.get(name) {
                if defs
                    .iter()
                    .any(|d| d.file == resolved.target_file && d.line == resolved.target_line)
                {
                    out.push((resolved.target_file.clone(), resolved.target_line));
                }
            }
        }
        out
    }
}

pub fn build_symbol_table(repo: &IrRepo) -> SymbolTable {
    SymbolTable::from_repo(repo)
}
