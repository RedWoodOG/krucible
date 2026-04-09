use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

impl Severity {
    pub fn as_level(&self) -> &'static str {
        match self {
            Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low | Severity::Info => "note",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum IssueType {
    DeadCode,
    FakeWiring,
    MissingHandler,
    UnusedImport,
    AiSlop,
    ContractViolation,
    UnresolvedAsync,
    CompilerDiagnostic,
    SecurityRisk,
}

impl IssueType {
    pub fn as_rule_id(&self) -> &'static str {
        match self {
            IssueType::DeadCode => "KRU001",
            IssueType::FakeWiring => "KRU002",
            IssueType::MissingHandler => "KRU003",
            IssueType::UnusedImport => "KRU004",
            IssueType::AiSlop => "KRU005",
            IssueType::ContractViolation => "KRU006",
            IssueType::UnresolvedAsync => "KRU007",
            IssueType::CompilerDiagnostic => "KRU008",
            IssueType::SecurityRisk => "KRU009",
        }
    }

    pub fn as_rule_name(&self) -> &'static str {
        match self {
            IssueType::DeadCode => "dead-code",
            IssueType::FakeWiring => "fake-wiring",
            IssueType::MissingHandler => "missing-handler",
            IssueType::UnusedImport => "unused-import",
            IssueType::AiSlop => "ai-slop",
            IssueType::ContractViolation => "contract-violation",
            IssueType::UnresolvedAsync => "unresolved-async",
            IssueType::CompilerDiagnostic => "compiler-diagnostic",
            IssueType::SecurityRisk => "security-risk",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Issue {
    pub issue_type: IssueType,
    pub severity: Severity,
    pub file: String,
    pub line: Option<usize>,
    pub message: String,
    pub claim: Option<String>,
    pub reality: Option<String>,
}

impl Issue {
    pub fn fingerprint(&self) -> String {
        let canonical = format!(
            "{}|{}|{}|{}",
            self.issue_type.as_rule_id(),
            self.file,
            self.line.unwrap_or(0),
            self.message.trim()
        );
        let mut hash = 0xcbf29ce484222325u64;
        for byte in canonical.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        format!("{hash:016x}")
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditReport {
    pub version: String,
    pub repo: String,
    pub files_scanned: usize,
    pub issues: Vec<Issue>,
}

impl AuditReport {
    pub fn new(repo: &str, files_scanned: usize) -> Self {
        Self {
            version: "0.1.0".into(),
            repo: repo.to_string(),
            files_scanned,
            issues: Vec::new(),
        }
    }

    pub fn high_count(&self) -> usize {
        self.issues
            .iter()
            .filter(|i| matches!(i.severity, Severity::High))
            .count()
    }

    pub fn medium_count(&self) -> usize {
        self.issues
            .iter()
            .filter(|i| matches!(i.severity, Severity::Medium))
            .count()
    }

    pub fn low_count(&self) -> usize {
        self.issues
            .iter()
            .filter(|i| matches!(i.severity, Severity::Low))
            .count()
    }

    pub fn to_sarif(&self) -> SarifLog {
        let rules = vec![
            sarif_rule(IssueType::DeadCode),
            sarif_rule(IssueType::FakeWiring),
            sarif_rule(IssueType::MissingHandler),
            sarif_rule(IssueType::UnusedImport),
            sarif_rule(IssueType::AiSlop),
            sarif_rule(IssueType::ContractViolation),
            sarif_rule(IssueType::UnresolvedAsync),
            sarif_rule(IssueType::CompilerDiagnostic),
            sarif_rule(IssueType::SecurityRisk),
        ];

        let results = self
            .issues
            .iter()
            .map(|issue| {
                let mut message = issue.message.clone();
                if let (Some(claim), Some(reality)) = (&issue.claim, &issue.reality) {
                    message = format!("{message}\nClaim: {claim}\nReality: {reality}");
                }

                SarifResult {
                    rule_id: issue.issue_type.as_rule_id().to_string(),
                    level: issue.severity.as_level().to_string(),
                    message: SarifMessage { text: message },
                    locations: vec![SarifLocation {
                        physical_location: SarifPhysicalLocation {
                            artifact_location: SarifArtifactLocation {
                                uri: issue.file.clone(),
                            },
                            region: issue.line.map(|line| SarifRegion { start_line: line }),
                        },
                    }],
                    partial_fingerprints: SarifPartialFingerprints {
                        primary_location_line_hash: issue.fingerprint(),
                    },
                }
            })
            .collect();

        SarifLog {
            version: "2.1.0".into(),
            schema: "https://json.schemastore.org/sarif-2.1.0.json".into(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "krucible".into(),
                        information_uri: "https://github.com/RedWoodOG/krucible".into(),
                        version: self.version.clone(),
                        rules,
                    },
                },
                results,
            }],
        }
    }

    pub fn to_json_report(&self) -> JsonReport {
        let issues = self
            .issues
            .iter()
            .map(|issue| JsonIssue {
                fingerprint: issue.fingerprint(),
                issue_type: issue.issue_type.clone(),
                severity: issue.severity.clone(),
                file: issue.file.clone(),
                line: issue.line,
                message: issue.message.clone(),
                claim: issue.claim.clone(),
                reality: issue.reality.clone(),
            })
            .collect();

        JsonReport {
            version: self.version.clone(),
            repo: self.repo.clone(),
            files_scanned: self.files_scanned,
            issues,
        }
    }

    pub fn to_baseline_snapshot(&self) -> BaselineSnapshot {
        let fingerprints: BTreeSet<String> = self.issues.iter().map(Issue::fingerprint).collect();
        BaselineSnapshot {
            version: self.version.clone(),
            repo: self.repo.clone(),
            files_scanned: self.files_scanned,
            fingerprints: fingerprints.into_iter().collect(),
        }
    }
}

fn sarif_rule(issue_type: IssueType) -> SarifRule {
    let level = match issue_type {
        IssueType::DeadCode => Severity::Medium.as_level(),
        IssueType::FakeWiring => Severity::High.as_level(),
        IssueType::MissingHandler => Severity::High.as_level(),
        IssueType::UnusedImport => Severity::Low.as_level(),
        IssueType::AiSlop => Severity::Medium.as_level(),
        IssueType::ContractViolation => Severity::High.as_level(),
        IssueType::UnresolvedAsync => Severity::Medium.as_level(),
        IssueType::CompilerDiagnostic => Severity::Medium.as_level(),
        IssueType::SecurityRisk => Severity::High.as_level(),
    };

    SarifRule {
        id: issue_type.as_rule_id().to_string(),
        name: issue_type.as_rule_name().to_string(),
        short_description: SarifMessage {
            text: format!("Krucible rule: {}", issue_type.as_rule_name()),
        },
        default_configuration: SarifDefaultConfiguration {
            level: level.to_string(),
        },
        help: SarifMessage {
            text: "Generated by Krucible structural code audit.".into(),
        },
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifLog {
    pub version: String,
    #[serde(rename = "$schema")]
    pub schema: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifDriver {
    pub name: String,
    pub information_uri: String,
    pub version: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    pub short_description: SarifMessage,
    pub default_configuration: SarifDefaultConfiguration,
    pub help: SarifMessage,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifDefaultConfiguration {
    pub level: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifResult {
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
    pub partial_fingerprints: SarifPartialFingerprints,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifPartialFingerprints {
    pub primary_location_line_hash: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifLocation {
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifPhysicalLocation {
    pub artifact_location: SarifArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<SarifRegion>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRegion {
    pub start_line: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonReport {
    pub version: String,
    pub repo: String,
    pub files_scanned: usize,
    pub issues: Vec<JsonIssue>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonIssue {
    pub fingerprint: String,
    pub issue_type: IssueType,
    pub severity: Severity,
    pub file: String,
    pub line: Option<usize>,
    pub message: String,
    pub claim: Option<String>,
    pub reality: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BaselineSnapshot {
    pub version: String,
    pub repo: String,
    pub files_scanned: usize,
    pub fingerprints: Vec<String>,
}
