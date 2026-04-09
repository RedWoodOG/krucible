use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub const TAINT_TAG_ANY: &str = "*";

#[derive(Debug, Clone)]
pub struct FlowPredicateSet {
    pub profile_name: String,
    pub source_names: Vec<String>,
    pub sink_names: Vec<String>,
    pub guard_names: Vec<String>,
    pub sanitizer_names: Vec<String>,
    pub sensitive_function_keywords: Vec<String>,
    pub source_models: Vec<FlowSourceModel>,
    pub sink_models: Vec<FlowSinkModel>,
    pub sanitizer_models: Vec<FlowSanitizerModel>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowSourceModel {
    pub pattern: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowSinkModel {
    pub pattern: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SanitizerStrength {
    Weak,
    Strong,
}

impl Default for SanitizerStrength {
    fn default() -> Self {
        Self::Strong
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowSanitizerModel {
    pub pattern: String,
    pub tags: Vec<String>,
    pub strength: SanitizerStrength,
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
    pub source_models: Vec<FlowPatternSpecInput>,
    #[serde(default)]
    pub sinks: Vec<String>,
    #[serde(default)]
    pub sink_models: Vec<FlowPatternSpecInput>,
    #[serde(default)]
    pub guards: Vec<String>,
    #[serde(default)]
    pub sanitizers: Vec<String>,
    #[serde(default)]
    pub sanitizer_models: Vec<FlowSanitizerSpecInput>,
    #[serde(default)]
    pub sensitive_functions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum FlowPatternSpecInput {
    Name(String),
    Tagged {
        pattern: String,
        #[serde(default)]
        tags: Vec<String>,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum FlowSanitizerSpecInput {
    Name(String),
    Typed {
        pattern: String,
        #[serde(default)]
        tags: Vec<String>,
        #[serde(default)]
        strength: SanitizerStrength,
    },
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
        let model = FlowModelProfile {
            sources: vec![],
            source_models: vec![],
            sinks: vec![
                "execute", "query", "delete", "update", "insert", "save", "fetch", "request",
                "post", "put", "patch", "invoke",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            sink_models: vec![],
            guards: vec![
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
            sanitizers: vec!["sanitize", "escape", "normalize"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            sanitizer_models: vec![],
            sensitive_functions: vec![
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
        };
        Self::from_model("generic_security".into(), model)
    }

    pub fn web_api() -> Self {
        let model = FlowModelProfile {
            sources: vec!["request", "req", "params", "body", "query"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            source_models: vec![],
            sinks: vec![
                "execute", "query", "delete", "update", "insert", "save", "fetch", "request",
                "post", "put", "patch", "invoke",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            sink_models: vec![],
            guards: vec![
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
            sanitizers: vec!["sanitize", "escape", "encode", "normalize"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            sanitizer_models: vec![],
            sensitive_functions: vec![
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
        };
        Self::from_model("web_api".into(), model)
    }

    pub fn from_model(name: String, model: FlowModelProfile) -> Self {
        let source_models = build_source_models(&model.sources, &model.source_models);
        let sink_models = build_sink_models(&model.sinks, &model.sink_models);
        let sanitizer_models = build_sanitizer_models(&model.sanitizers, &model.sanitizer_models);
        let sanitizer_names: Vec<String> = sanitizer_models
            .iter()
            .filter(|s| s.strength == SanitizerStrength::Strong)
            .map(|s| s.pattern.clone())
            .collect();

        Self {
            profile_name: name,
            source_names: source_models.iter().map(|m| m.pattern.clone()).collect(),
            sink_names: sink_models.iter().map(|m| m.pattern.clone()).collect(),
            guard_names: normalize_list(model.guards),
            sanitizer_names,
            sensitive_function_keywords: normalize_list(model.sensitive_functions),
            source_models,
            sink_models,
            sanitizer_models,
        }
    }

    pub fn is_sensitive_function(&self, fn_name: &str) -> bool {
        match_any_substr(&self.sensitive_function_keywords, fn_name)
    }

    pub fn is_source(&self, call_name: &str) -> bool {
        !self.source_tags_for_call(call_name).is_empty()
    }

    pub fn is_sink(&self, call_name: &str) -> bool {
        !self.sink_tags_for_call(call_name).is_empty()
    }

    pub fn is_guard(&self, call_name: &str) -> bool {
        match_any_substr(&self.guard_names, call_name)
            || match_any_substr(&self.sanitizer_names, call_name)
    }

    pub fn source_tags_for_call(&self, call_name: &str) -> Vec<String> {
        collect_tags(
            self.source_models
                .iter()
                .filter(|m| match_substr(call_name, &m.pattern))
                .map(|m| m.tags.clone()),
        )
    }

    pub fn sink_tags_for_call(&self, call_name: &str) -> Vec<String> {
        collect_tags(
            self.sink_models
                .iter()
                .filter(|m| match_substr(call_name, &m.pattern))
                .map(|m| m.tags.clone()),
        )
    }

    pub fn matching_sanitizers_for_call(&self, call_name: &str) -> Vec<&FlowSanitizerModel> {
        self.sanitizer_models
            .iter()
            .filter(|m| match_substr(call_name, &m.pattern))
            .collect()
    }
}

fn normalize_list(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|v| v.trim().to_lowercase())
        .filter(|v| !v.is_empty())
        .collect()
}

fn normalize_tags(mut values: Vec<String>) -> Vec<String> {
    values = normalize_list(values);
    if values.is_empty() {
        return vec![TAINT_TAG_ANY.to_string()];
    }
    values.sort();
    values.dedup();
    values
}

fn build_source_models(
    legacy_sources: &[String],
    typed_sources: &[FlowPatternSpecInput],
) -> Vec<FlowSourceModel> {
    let mut out = Vec::new();
    out.extend(legacy_sources.iter().map(|pattern| FlowSourceModel {
        pattern: pattern.trim().to_lowercase(),
        tags: vec![TAINT_TAG_ANY.to_string()],
    }));
    out.extend(typed_sources.iter().map(|spec| match spec {
        FlowPatternSpecInput::Name(pattern) => FlowSourceModel {
            pattern: pattern.trim().to_lowercase(),
            tags: vec![TAINT_TAG_ANY.to_string()],
        },
        FlowPatternSpecInput::Tagged { pattern, tags } => FlowSourceModel {
            pattern: pattern.trim().to_lowercase(),
            tags: normalize_tags(tags.clone()),
        },
    }));
    normalize_source_models(out)
}

fn build_sink_models(
    legacy_sinks: &[String],
    typed_sinks: &[FlowPatternSpecInput],
) -> Vec<FlowSinkModel> {
    let mut out = Vec::new();
    out.extend(legacy_sinks.iter().map(|pattern| FlowSinkModel {
        pattern: pattern.trim().to_lowercase(),
        tags: vec![TAINT_TAG_ANY.to_string()],
    }));
    out.extend(typed_sinks.iter().map(|spec| match spec {
        FlowPatternSpecInput::Name(pattern) => FlowSinkModel {
            pattern: pattern.trim().to_lowercase(),
            tags: vec![TAINT_TAG_ANY.to_string()],
        },
        FlowPatternSpecInput::Tagged { pattern, tags } => FlowSinkModel {
            pattern: pattern.trim().to_lowercase(),
            tags: normalize_tags(tags.clone()),
        },
    }));
    normalize_sink_models(out)
}

fn build_sanitizer_models(
    legacy_sanitizers: &[String],
    typed_sanitizers: &[FlowSanitizerSpecInput],
) -> Vec<FlowSanitizerModel> {
    let mut out = Vec::new();
    out.extend(legacy_sanitizers.iter().map(|pattern| FlowSanitizerModel {
        pattern: pattern.trim().to_lowercase(),
        tags: vec![TAINT_TAG_ANY.to_string()],
        strength: SanitizerStrength::Strong,
    }));
    out.extend(typed_sanitizers.iter().map(|spec| match spec {
        FlowSanitizerSpecInput::Name(pattern) => FlowSanitizerModel {
            pattern: pattern.trim().to_lowercase(),
            tags: vec![TAINT_TAG_ANY.to_string()],
            strength: SanitizerStrength::Strong,
        },
        FlowSanitizerSpecInput::Typed {
            pattern,
            tags,
            strength,
        } => FlowSanitizerModel {
            pattern: pattern.trim().to_lowercase(),
            tags: normalize_tags(tags.clone()),
            strength: *strength,
        },
    }));
    normalize_sanitizer_models(out)
}

fn normalize_source_models(models: Vec<FlowSourceModel>) -> Vec<FlowSourceModel> {
    let mut by_pattern: HashMap<String, Vec<String>> = HashMap::new();
    for model in models {
        if model.pattern.is_empty() {
            continue;
        }
        by_pattern.entry(model.pattern).or_default().extend(model.tags);
    }

    let mut out: Vec<FlowSourceModel> = by_pattern
        .into_iter()
        .map(|(pattern, tags)| FlowSourceModel {
            pattern,
            tags: normalize_tags(tags),
        })
        .collect();
    out.sort_by(|a, b| a.pattern.cmp(&b.pattern));
    out
}

fn normalize_sink_models(models: Vec<FlowSinkModel>) -> Vec<FlowSinkModel> {
    let mut by_pattern: HashMap<String, Vec<String>> = HashMap::new();
    for model in models {
        if model.pattern.is_empty() {
            continue;
        }
        by_pattern.entry(model.pattern).or_default().extend(model.tags);
    }

    let mut out: Vec<FlowSinkModel> = by_pattern
        .into_iter()
        .map(|(pattern, tags)| FlowSinkModel {
            pattern,
            tags: normalize_tags(tags),
        })
        .collect();
    out.sort_by(|a, b| a.pattern.cmp(&b.pattern));
    out
}

fn normalize_sanitizer_models(models: Vec<FlowSanitizerModel>) -> Vec<FlowSanitizerModel> {
    let mut by_pattern: HashMap<String, (Vec<String>, SanitizerStrength)> = HashMap::new();
    for model in models {
        if model.pattern.is_empty() {
            continue;
        }
        let entry = by_pattern
            .entry(model.pattern)
            .or_insert_with(|| (Vec::new(), SanitizerStrength::Weak));
        entry.0.extend(model.tags);
        if model.strength > entry.1 {
            entry.1 = model.strength;
        }
    }

    let mut out: Vec<FlowSanitizerModel> = by_pattern
        .into_iter()
        .map(|(pattern, (tags, strength))| FlowSanitizerModel {
            pattern,
            tags: normalize_tags(tags),
            strength,
        })
        .collect();
    out.sort_by(|a, b| a.pattern.cmp(&b.pattern));
    out
}

fn match_any_substr(patterns: &[String], value: &str) -> bool {
    let lower = value.to_lowercase();
    patterns.iter().any(|pattern| lower.contains(pattern))
}

fn collect_tags<T>(tag_sets: T) -> Vec<String>
where
    T: Iterator<Item = Vec<String>>,
{
    let mut tags: Vec<String> = tag_sets.flatten().collect();
    if tags.is_empty() {
        return Vec::new();
    }
    tags = normalize_tags(tags);
    tags
}

fn match_substr(value: &str, pattern: &str) -> bool {
    value.to_lowercase().contains(pattern)
}

#[cfg(test)]
mod tests {
    use super::{parse_model_json, FlowPredicateSet, SanitizerStrength, TAINT_TAG_ANY};

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
              "source_models": [{ "pattern": "payload", "tags": ["pii"] }],
              "sinks": ["execute"],
              "sink_models": [{ "pattern": "write_audit", "tags": ["audit"] }],
              "guards": ["validate"],
              "sanitizers": ["escape"],
              "sanitizer_models": [{ "pattern": "maskPii", "tags": ["pii"], "strength": "strong" }],
              "sensitive_functions": ["admin"]
            }
          }
        }"#;
        let file = parse_model_json(raw).expect("model json should parse");
        let profile = file.profiles.get("custom").expect("custom profile missing");
        let set = FlowPredicateSet::from_model("custom".into(), profile.clone());
        assert!(set.is_source("request_body"));
        assert!(set.is_source("payload_writer"));
        assert!(set.is_sink("db_execute"));
        assert!(set.is_sink("write_audit_event"));
        assert!(set.is_guard("escape_html"));
        let sanitizers = set.matching_sanitizers_for_call("maskPiiValue");
        assert_eq!(sanitizers.len(), 1);
        assert_eq!(sanitizers[0].strength, SanitizerStrength::Strong);
        assert!(set.is_sensitive_function("adminDeleteUser"));
        assert!(set.source_tags_for_call("payload_writer").contains(&"pii".to_string()));
        assert!(set
            .sink_tags_for_call("db_execute")
            .contains(&TAINT_TAG_ANY.to_string()));
    }
}
