use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct FlowPredicateSet {
    pub profile_name: String,
    pub source_names: Vec<String>,
    pub sink_names: Vec<String>,
    pub guard_names: Vec<String>,
    pub sanitizer_names: Vec<String>,
    pub sensitive_function_keywords: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FlowModelFile {
    pub profiles: HashMap<String, FlowModelProfile>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FlowModelProfile {
    #[serde(default)]
    pub sources: Vec<String>,
    #[serde(default)]
    pub sinks: Vec<String>,
    #[serde(default)]
    pub guards: Vec<String>,
    #[serde(default)]
    pub sanitizers: Vec<String>,
    #[serde(default)]
    pub sensitive_functions: Vec<String>,
}

pub fn generic_security() -> FlowPredicateSet {
    FlowPredicateSet::generic_security()
}

pub fn web_api() -> FlowPredicateSet {
    FlowPredicateSet::web_api()
}

pub fn generic_security_policy() -> FlowPredicateSet {
    FlowPredicateSet::generic_security()
}

pub fn web_api_policy() -> FlowPredicateSet {
    FlowPredicateSet::web_api()
}

pub fn default_policies() -> Vec<FlowPredicateSet> {
    vec![generic_security_policy(), web_api_policy()]
}

pub fn load_policies(repo_root: &Path, explicit_model_path: Option<&Path>) -> Result<Vec<FlowPredicateSet>> {
    let selected_path = explicit_model_path
        .map(PathBuf::from)
        .or_else(|| discover_default_model_path(repo_root));

    if let Some(path) = selected_path {
        return load_policies_from_file(&path);
    }

    Ok(default_policies())
}

pub fn discover_default_model_path(repo_root: &Path) -> Option<PathBuf> {
    let discovered = repo_root.join(".krucible/flow-models.json");
    discovered.exists().then_some(discovered)
}

pub fn load_policies_from_file(path: &Path) -> Result<Vec<FlowPredicateSet>> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("Failed reading flow model file '{}'", path.display()))?;
    let parsed = parse_model_json(&raw)
        .with_context(|| format!("Failed parsing flow model JSON from '{}'", path.display()))?;

    let mut items: Vec<_> = parsed.profiles.into_iter().collect();
    items.sort_by(|a, b| a.0.cmp(&b.0));

    let policies: Vec<FlowPredicateSet> = items
        .into_iter()
        .map(|(name, profile)| FlowPredicateSet::from_model(name, profile))
        .collect();

    if policies.is_empty() {
        anyhow::bail!(
            "Flow model file '{}' contains no profiles",
            path.display()
        );
    }

    Ok(policies)
}

pub fn parse_model_json(raw: &str) -> Result<FlowModelFile> {
    let parsed: FlowModelFile = serde_json::from_str(raw)?;
    Ok(parsed)
}

impl FlowPredicateSet {
    pub fn generic_security() -> Self {
        Self {
            profile_name: "generic_security".into(),
            source_names: vec![],
            sink_names: vec![
                "execute", "query", "delete", "update", "insert", "save", "fetch", "request",
                "post", "put", "patch", "invoke",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            guard_names: vec![
                "validate",
                "verify",
                "authorize",
                "authenticate",
                "check_permission",
                "guard",
                "sanitize",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            sanitizer_names: vec!["sanitize", "escape", "normalize"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            sensitive_function_keywords: vec![
                "auth",
                "login",
                "permission",
                "token",
                "delete",
                "update",
                "charge",
                "payment",
                "admin",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
        }
    }

    pub fn web_api() -> Self {
        Self {
            profile_name: "web_api".into(),
            source_names: vec!["request", "req", "params", "body", "query"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            sink_names: vec![
                "execute", "query", "delete", "update", "insert", "save", "fetch", "request",
                "post", "put", "patch", "invoke",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            guard_names: vec![
                "validate",
                "verify",
                "authorize",
                "authenticate",
                "check_permission",
                "guard",
                "sanitize",
                "escape",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            sanitizer_names: vec!["sanitize", "escape", "encode", "normalize"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            sensitive_function_keywords: vec![
                "auth",
                "login",
                "permission",
                "token",
                "delete",
                "update",
                "charge",
                "payment",
                "admin",
                "user",
                "profile",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
        }
    }

    pub fn from_model(name: String, model: FlowModelProfile) -> Self {
        Self {
            profile_name: name,
            source_names: normalize_list(model.sources),
            sink_names: normalize_list(model.sinks),
            guard_names: normalize_list(model.guards),
            sanitizer_names: normalize_list(model.sanitizers),
            sensitive_function_keywords: normalize_list(model.sensitive_functions),
        }
    }

    pub fn is_sensitive_function(&self, fn_name: &str) -> bool {
        match_any_substr(&self.sensitive_function_keywords, fn_name)
    }

    pub fn is_source(&self, call_name: &str) -> bool {
        match_any_substr(&self.source_names, call_name)
    }

    pub fn is_sink(&self, call_name: &str) -> bool {
        match_any_substr(&self.sink_names, call_name)
    }

    pub fn is_guard(&self, call_name: &str) -> bool {
        match_any_substr(&self.guard_names, call_name)
            || match_any_substr(&self.sanitizer_names, call_name)
    }
}

fn normalize_list(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|v| v.trim().to_lowercase())
        .filter(|v| !v.is_empty())
        .collect()
}

fn match_any_substr(patterns: &[String], value: &str) -> bool {
    let lower = value.to_lowercase();
    patterns.iter().any(|pattern| lower.contains(pattern))
}

#[cfg(test)]
mod tests {
    use super::{parse_model_json, FlowPredicateSet};

    #[test]
    fn generic_set_marks_auth_function_sensitive() {
        let p = FlowPredicateSet::generic_security();
        assert!(p.is_sensitive_function("authorizePayment"));
    }

    #[test]
    fn generic_set_ignores_unrelated_function_name() {
        let p = FlowPredicateSet::generic_security();
        assert!(!p.is_sensitive_function("renderHeader"));
    }

    #[test]
    fn parses_model_json_and_builds_profile() {
        let raw = r#"
        {
          "profiles": {
            "custom": {
              "sources": ["request"],
              "sinks": ["execute"],
              "guards": ["validate"],
              "sanitizers": ["escape"],
              "sensitive_functions": ["admin"]
            }
          }
        }"#;
        let file = parse_model_json(raw).expect("model json should parse");
        let profile = file.profiles.get("custom").expect("custom profile missing");
        let set = FlowPredicateSet::from_model("custom".into(), profile.clone());
        assert!(set.is_source("request_body"));
        assert!(set.is_sink("db_execute"));
        assert!(set.is_guard("escape_html"));
        assert!(set.is_sensitive_function("adminDeleteUser"));
    }
}
