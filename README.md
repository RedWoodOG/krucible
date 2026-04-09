# Krucible

**Is your code real, or just glue?**

Krucible is a structural code verification CLI that detects dead wiring, fake logic, and AI-generated slop in any repository — before it ships.

## What It Checks

- **Wiring Reality** — functions defined but never called, dead imports, missing handlers
- **Execution Paths** — async paths that never resolve, functions that return nothing
- **AI Slop** — placeholder logic, TODO-driven development, suspiciously empty code
- **Contract Violations** — function signatures that don't match usage
- **Reality Gap** — what the code *claims* to do vs what it *actually* does

## Usage

```bash
krucible ./path/to/repo
krucible ./path/to/repo --format json
krucible ./path/to/repo --format sarif
krucible ./path/to/repo --format json --output report.json
krucible ./path/to/repo --format sarif --output report.sarif.json
krucible ./path/to/repo --flow-model ./.krucible/flow-models.json
krucible ./path/to/repo --write-baseline baseline.json
krucible ./path/to/repo --baseline baseline.json --only-new --format sarif
krucible ./path/to/repo --max-high 0 --max-medium 5 --max-low 20
```

## CI / Baseline Workflow

- Create a baseline snapshot of current findings:
  - `krucible ./repo --write-baseline baseline.json`
- In CI, report only new findings relative to baseline:
  - `krucible ./repo --baseline baseline.json --only-new --format sarif --output report.sarif.json`
- Enforce policy thresholds:
  - `--max-high N --max-medium N --max-low N`
  - If no thresholds are provided, default policy is unchanged: fail when HIGH findings exist.

## Flow Model Configuration

- Optional flow policy file:
  - `--flow-model ./.krucible/flow-models.json`
- If omitted, Krucible uses built-in profiles (`generic_security`, `web_api`).
- File schema:

```json
{
  "profiles": {
    "custom_profile": {
      "sources": ["request", "body"],
      "source_models": [
        { "pattern": "request", "tags": ["pii"] },
        { "pattern": "payload", "tags": ["payment"] }
      ],
      "sinks": ["execute", "invoke"],
      "sink_models": [
        { "pattern": "execute", "tags": ["pii"] },
        { "pattern": "charge", "tags": ["payment"] }
      ],
      "guards": ["validate", "authorize"],
      "sanitizers": ["escape", "sanitize"],
      "sanitizer_models": [
        { "pattern": "mask", "tags": ["pii"], "strength": "strong" },
        { "pattern": "normalize", "tags": ["payment"], "strength": "weak" }
      ],
      "sensitive_functions": ["admin", "payment", "auth"]
    }
  }
}
```

- Typed model notes:
  - `source_models` / `sink_models` tags define taint categories (e.g. `pii`, `payment`).
  - `sanitizer_models` supports `strength: "strong" | "weak"`.
    - `strong` sanitizers clear matching taint tags.
    - `weak` sanitizers annotate intent but do not clear taint in guarded-sink checks.
  - Legacy string lists (`sources`, `sinks`, `sanitizers`) are still supported and treated as wildcard-tag (`*`) models.

## Supported Languages (v1)

- TypeScript / JavaScript
- Rust

## Status

🚧 Phase 1 — Scanner (in progress)

## Build

```bash
cargo build --release
./target/release/krucible ./some-repo
```
