# Generated Artifacts Directory Structure

This directory contains detection rules and artifacts in various stages of the pipeline.

## Directory Layout

```
generated/
├── sigma_rules/              # STAGING: Draft rules from agent (cleaned on PR)
├── tests/                    # STAGING: Test payloads for draft rules (cleaned on PR)
├── production_rules/         # PRODUCTION: Human-approved final rules
│   ├── *.yml                # Production Sigma rules
│   └── metadata/            # Rule metadata (quality scores, approval timestamps)
├── STATIC_QUALITY_REPORT.json    # Static LLM judge evaluation
├── PASSING_RULE_IDS.json         # Rules that passed quality gate
├── ELK_QUERIES.json              # Converted Elasticsearch queries  
├── ELK_VALIDATION_REPORT.json    # ELK query validation results
└── INTEGRATION_TEST_RESULTS.json # Real ELK integration test metrics
```

## Pipeline Flow

1. **Generation** → `sigma_rules/` + `tests/`
   - Agent generates draft Sigma rules and test payloads
   - Static LLM judge filters low-quality rules

2. **Validation** → Quality reports
   - Unit tests verify Sigma syntax
   - Convert to ELK queries and validate
   - Integration tests run against real Elasticsearch
   - LLM judge evaluates based on test results

3. **Human Review** → PR created
   - Staged rules moved to PR for human review
   - Reviewer checks rule logic, quality metrics, test coverage

4. **Production** → `production_rules/`
   - After PR approval, rules moved to production_rules/
   - Staging artifacts (sigma_rules/, tests/) cleaned up
   - Production rules deployed to SIEM

## File Lifecycle

- **Staging files** (sigma_rules/, tests/): Ephemeral, regenerated on each run
- **Quality reports**: Committed to track evaluation history
- **Production rules**: Persistent, only updated via human-approved PRs

## Cleanup

Run `scripts/cleanup_staging.sh` to remove all staging artifacts before a fresh generation run.
