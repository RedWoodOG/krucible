use serde::{Deserialize, Serialize};

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
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Issue {
    pub issue_type: IssueType,
    pub severity: Severity,
    pub file: String,
    pub line: Option<usize>,
    pub message: String,
    pub claim: Option<String>,
    pub reality: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
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
        self.issues.iter().filter(|i| matches!(i.severity, Severity::High)).count()
    }

    pub fn medium_count(&self) -> usize {
        self.issues.iter().filter(|i| matches!(i.severity, Severity::Medium)).count()
    }

    pub fn low_count(&self) -> usize {
        self.issues.iter().filter(|i| matches!(i.severity, Severity::Low)).count()
    }
}
