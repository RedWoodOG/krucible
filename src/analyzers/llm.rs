use anyhow::Result;
use serde::{Deserialize, Serialize};
use crate::parser::tree_sitter::ParsedFile;
use crate::report::schema::{Issue, IssueType, Severity};

const LITELLM_URL: &str = "http://localhost:4000/v1/chat/completions";
const LITELLM_KEY: &str = "sk-litellm-local";
const MODEL: &str = "qwen";
const MAX_TOKENS: u32 = 800;
// Max chars of function source to send to the model
const MAX_FN_CHARS: usize = 1200;

#[derive(Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    max_tokens: u32,
    temperature: f32,
}

#[derive(Serialize, Deserialize, Clone)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: ChatMessage,
}

/// LLM verdict for a single function
#[derive(Deserialize, Debug)]
struct FunctionVerdict {
    /// "ok" | "gap" | "stub" | "slop"
    verdict: String,
    severity: String,
    claim: String,
    reality: String,
    reason: String,
}

fn call_llm(prompt: &str) -> Result<String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(90))
        .build()?;

    let req = ChatRequest {
        model: MODEL.to_string(),
        messages: vec![
            ChatMessage {
                role: "system".to_string(),
                content: "You are a code auditor. You analyze functions and detect when their name implies behavior that the code does not actually implement. Respond ONLY with valid JSON, no markdown, no explanation.".to_string(),
            },
            ChatMessage {
                role: "user".to_string(),
                content: prompt.to_string(),
            },
        ],
        max_tokens: MAX_TOKENS,
        temperature: 0.1,
    };

    let resp = client
        .post(LITELLM_URL)
        .header("Authorization", format!("Bearer {}", LITELLM_KEY))
        .header("Content-Type", "application/json")
        .json(&req)
        .send()?;

    if !resp.status().is_success() {
        anyhow::bail!("LLM request failed: {}", resp.status());
    }

    let chat: ChatResponse = resp.json()?;
    let content = chat.choices
        .into_iter()
        .next()
        .map(|c| c.message.content)
        .ok_or_else(|| anyhow::anyhow!("Empty LLM response"))?;

    Ok(content)
}

fn build_prompt(fn_name: &str, fn_source: &str, file: &str) -> String {
    format!(
        r#"Analyze this function from file "{file}".

Function name: {fn_name}
Source code:
```
{fn_source}
```

Does the function name make a claim about what it does that the code does NOT actually fulfill?

Examples of gaps:
- "saveUser" but no database call exists
- "authenticate" but no password check, token verify, or hash comparison exists
- "sendEmail" but no mail client or SMTP call exists
- "processPayment" but returns a mock object
- "fetchData" but no HTTP call exists

If the code is fine (it does what the name claims), respond with verdict "ok".

Respond ONLY with this exact JSON structure:
{{
  "verdict": "ok" | "gap" | "stub" | "slop",
  "severity": "high" | "medium" | "low",
  "claim": "what the function name implies it does",
  "reality": "what the code actually does",
  "reason": "one sentence explanation"
}}"#
    )
}

/// Extract the source text of each function using line numbers from the parse result.
/// This is a best-effort extraction: grab lines from fn start to a reasonable end.
fn extract_function_source(content: &str, start_line: usize) -> String {
    let lines: Vec<&str> = content.lines().collect();
    if start_line == 0 || start_line > lines.len() {
        return String::new();
    }

    let start = start_line - 1;
    let mut brace_depth: i32 = 0;
    let mut end = start;
    let mut found_open = false;

    for (i, line) in lines[start..].iter().enumerate() {
        for ch in line.chars() {
            match ch {
                '{' => { brace_depth += 1; found_open = true; }
                '}' => { brace_depth -= 1; }
                _ => {}
            }
        }
        end = start + i;
        if found_open && brace_depth <= 0 {
            break;
        }
        // Safety: don't grab more than 60 lines
        if i > 60 { break; }
    }

    lines[start..=end].join("\n").chars().take(MAX_FN_CHARS).collect()
}

pub fn analyze(files: &[ParsedFile], source_map: &std::collections::HashMap<String, String>) -> Vec<Issue> {
    let mut issues = Vec::new();

    // Only analyze functions with action-verb names — these are the ones that make claims
    let action_prefixes = [
        "create", "save", "update", "delete", "send", "fetch", "get", "load",
        "authenticate", "authorize", "validate", "verify", "process", "handle",
        "submit", "upload", "sync", "generate", "build", "execute", "run",
        "store", "persist", "write", "read", "parse", "transform", "convert",
        "notify", "email", "pay", "charge", "register", "login", "logout",
    ];

    for file in files {
        let source = match source_map.get(&file.file) {
            Some(s) => s,
            None => continue,
        };

        for func in &file.functions {
            let name_lower = func.name.to_lowercase();

            // Skip functions that don't make behavioral claims
            if !action_prefixes.iter().any(|p| name_lower.starts_with(p) || name_lower.contains(p)) {
                continue;
            }

            // Skip very short functions — not worth the LLM call
            let fn_source = extract_function_source(source, func.line);
            if fn_source.lines().count() < 3 {
                continue;
            }

            let prompt = build_prompt(&func.name, &fn_source, &file.file);

            match call_llm(&prompt) {
                Ok(response) => {
                    // Strip markdown code fences if model added them
                    let clean = response
                        .trim()
                        .trim_start_matches("```json")
                        .trim_start_matches("```")
                        .trim_end_matches("```")
                        .trim();

                    match serde_json::from_str::<FunctionVerdict>(clean) {
                        Ok(verdict) => {
                            if verdict.verdict == "ok" {
                                continue;
                            }

                            let severity = match verdict.severity.as_str() {
                                "high" => Severity::High,
                                "medium" => Severity::Medium,
                                _ => Severity::Low,
                            };

                            issues.push(Issue {
                                issue_type: IssueType::ContractViolation,
                                severity,
                                file: file.file.clone(),
                                line: Some(func.line),
                                message: format!("[AI] Reality gap in `{}()`: {}", func.name, verdict.reason),
                                claim: Some(verdict.claim),
                                reality: Some(verdict.reality),
                            });
                        }
                        Err(e) => {
                            eprintln!("  [llm] Failed to parse verdict for {}: {}\n  raw: {}", func.name, e, &response[..response.len().min(300)]);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("  [llm] Request failed for {}: {}", func.name, e);
                }
            }
        }
    }

    issues
}
