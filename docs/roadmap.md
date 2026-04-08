# Krucible Roadmap to CodeQL-Class Capability

This roadmap defines the engineering path from the current heuristic scanner to a semantic security analyzer with CI-grade integration.

## Guiding Principles

- Keep current strengths: wiring integrity, reality-gap checks, AI slop detection.
- Add semantic depth incrementally: symbol resolution, control/data flow, taint.
- Keep output stable and automation-friendly (JSON + SARIF + deterministic issue IDs).
- Prefer test-first additions for each new subsystem.

## Epic 1: Productization Foundation (Output + CI Contract)

### Story 1.1: SARIF output mode
- Description: Add first-class SARIF 2.1.0 output for GitHub/code scanning compatibility.
- Status: Completed
- Acceptance criteria:
  - CLI supports `--format sarif`.
  - SARIF includes tool metadata, rules, results, severities, file locations.
  - Output validates in common SARIF consumers.

### Story 1.2: Stable issue fingerprints
- Description: Add deterministic fingerprints to results to support baseline/diff workflows.
- Status: Completed
- Acceptance criteria:
  - Each issue has stable ID hash from (rule, file, line, normalized message).
  - Same issue in repeated runs retains same fingerprint.

### Story 1.3: CI gate policy flags
- Description: Add CLI policy controls for failing thresholds.
- Status: Completed
- Acceptance criteria:
  - Flags for max allowed HIGH/MEDIUM/LOW.
  - Exit codes reflect policy violations.

## Epic 2: Semantic Core (IR + Symbol Resolution)

### Story 2.1: Normalized Intermediate Representation (IR)
- Description: Introduce a language-agnostic IR for functions, calls, modules, imports, and symbols.
- Status: In progress (IR scaffold added; wiring analyzer migrated to IR path)
- Acceptance criteria:
  - Rust + TS/JS frontends emit IR with equivalent semantic fields.
  - Existing analyzers can run from IR adapter.

### Story 2.2: Cross-file symbol table
- Description: Resolve declarations/usages across modules and files.
- Acceptance criteria:
  - Call sites resolve to candidate definitions with confidence scores.
  - Dead-code analyzer uses symbol resolution instead of name-only matching.

### Story 2.3: Type/context enrichment
- Description: Attach minimal type/context metadata needed for higher-confidence rules.
- Acceptance criteria:
  - IR nodes include visibility, async, return-shape hints.
  - Rule engine can filter on type/context predicates.

## Epic 3: Control Flow + Interprocedural Dataflow

### Story 3.1: Function-level CFG
- Description: Build control-flow graphs for supported languages.
- Acceptance criteria:
  - CFG includes branches, loops, returns, and error paths.
  - Unit tests cover representative syntax patterns.

### Story 3.2: Intra-procedural dataflow engine
- Description: Track value flow and state transitions within a function.
- Acceptance criteria:
  - Engine supports forward/backward flow queries.
  - Rules can query "value reaches sink without guard."

### Story 3.3: Interprocedural call flow
- Description: Propagate flow facts across call boundaries.
- Acceptance criteria:
  - Dataflow follows function calls with depth control.
  - Performance budget documented and tested on fixture repos.

## Epic 4: Taint Analysis and Security Rule Packs

### Story 4.1: Source/sink/sanitizer model
- Description: Define taint primitives per language/framework.
- Acceptance criteria:
  - Configurable model files for sources/sinks/sanitizers.
  - Runtime supports custom model overrides.

### Story 4.2: Security MVP rules
- Description: Implement initial CWE-aligned set.
- Acceptance criteria:
  - Path traversal, command injection, SSRF, SQL injection MVP checks.
  - Rule docs include rationale, false-positive notes, examples.

### Story 4.3: Framework-aware packs
- Description: Add framework-specific security packs (Tauri, Node/Express).
- Acceptance criteria:
  - Rules understand framework idioms and sanitizers.
  - Reduced false positives vs generic heuristics.

## Epic 5: Query Model and Rule Authoring UX

### Story 5.1: Declarative rule DSL
- Description: Move from hardcoded Rust analyzers toward declarative rule definitions.
- Acceptance criteria:
  - Rules can express pattern + flow predicates + severity mapping.
  - Rule loader supports versioned packs.

### Story 5.2: Rule test harness
- Description: Add fixture-driven expected findings tests.
- Acceptance criteria:
  - Each rule has positive/negative fixtures.
  - CI enforces no regression in precision/recall on golden fixtures.

### Story 5.3: Performance guardrails
- Description: Add profiling and performance budgets to prevent pathological scans.
- Acceptance criteria:
  - Benchmarks run in CI.
  - Regression threshold alerts on runtime/memory.

## Epic 6: Enterprise Readiness

### Story 6.1: Baseline and diff mode
- Description: Compare current findings against baseline for incremental adoption.
- Acceptance criteria:
  - CLI can save baseline and report new/resolved findings.
  - Works across JSON and SARIF.

### Story 6.2: Suppressions and metadata governance
- Description: Support local suppressions with auditable metadata.
- Acceptance criteria:
  - Suppression requires reason + optional expiration.
  - Suppressed findings remain visible in audit mode.

### Story 6.3: Reporting and telemetry hooks
- Description: Add optional telemetry and summary exports for trend tracking.
- Acceptance criteria:
  - Opt-in only.
  - Exports aggregate metrics (issue counts by rule/severity over time).

## Release Milestones

- R1 (Near-term): Epic 1 complete + partial Epic 2 (IR skeleton).
- R2: Epic 2 and Epic 3 complete; dead-code/wiring moved to semantic engine.
- R3: Epic 4 MVP security pack with strong test coverage.
- R4: Epic 5 DSL + test harness + performance budgets.
- R5: Epic 6 enterprise workflows.

## Immediate Implementation Order

1. Story 1.1 (SARIF output) - starts now.
2. Story 1.2 (stable fingerprints).
3. Story 2.1 (normalized IR scaffold).
4. Story 2.2 (symbol table integration into wiring analyzer).
