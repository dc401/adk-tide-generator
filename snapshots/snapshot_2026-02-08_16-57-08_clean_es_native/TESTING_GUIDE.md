# Testing Guide - Full Pipeline

## Prerequisites

```bash
pip install -r requirements.txt
export GOOGLE_CLOUD_PROJECT=your-project-id
```

## Full Pipeline Test (Local)

### Step 1: Generate Detection Rules

```bash
python run_agent.py \
  --cti-folder cti_src \
  --output generated \
  --project $GOOGLE_CLOUD_PROJECT
```

**Expected Output:**
- 3-4 YAML rules in `generated/detection_rules/`
- CTI context in `generated/cti_context.yml`
- Security scan PASS
- Validation scores ≥0.75

**What to Check:**
- Rules have valid Lucene queries?
- Test cases include TP, FN, FP, TN?
- MITRE TTPs correctly mapped?

---

### Step 2: Validation Pipeline

```bash
python scripts/validate_rules.py \
  --rules-dir generated/detection_rules \
  --staging-dir generated/staging \
  --output validation_report.yml \
  --project $GOOGLE_CLOUD_PROJECT
```

**Expected Output:**
```
[Validate] akira_ransomware_-_shadow_copy_deletion_(t1490)
  [1/3] Lucene syntax check...
    Query: event.code:1 AND process.name:vssadmin.exe AND process.command_line:*delete shadows*...
    ✓ PASS
    Operators: AND=2, OR=0, NOT=0, wildcards=2
  [2/3] YAML → JSON conversion...
    ✓ PASS (3856 bytes)
  [3/3] LLM schema validation (with research)...
    Calling Gemini Pro to validate against ES schema...
    ✓ PASS - Schema validation successful
    Schema compliance:
      ✓ required_fields: pass
      ✓ data_types: pass
      ✓ query_syntax: pass
      ✓ ecs_fields: pass
      ✓ threat_mapping: pass
    Research references:
      - https://www.elastic.co/guide/en/elasticsearch/reference/8.12/...
      - https://www.elastic.co/guide/en/ecs/current/...
      - https://github.com/elastic/detection-rules/...
```

**What to Check:**
- All rules PASS all 3 stages?
- Lucene syntax valid?
- JSON conversion successful?
- LLM found ECS fields in official docs?

**If Validation Fails:**
- Check `validation_report.yml` for detailed errors
- Look at "fixes_needed" field for actionable items
- Fix and re-run

---

### Step 3: Integration Testing

```bash
python scripts/integration_test_ci.py \
  --rules-dir generated/detection_rules \
  --output integration_test_results.yml
```

**Expected Output:**
```
[1/7] Installing Elasticsearch...
[2/7] Starting Elasticsearch...
  ✓ Elasticsearch healthy (status: yellow)
[3/7] Creating test index...
  ✓ Created index: test-logs
[4/7] Ingesting test payloads...
  ✓ akira_ransomware_-_shadow_copy_deletion: 4 payloads
  Total: 12 payloads
[5/7] Executing detection rules...
  akira_ransomware_-_shadow_copy_deletion
    Matched: 2 docs
[6/7] Calculating metrics...
  akira_ransomware_-_shadow_copy_deletion:
    TP: 2/2, FN: 0/1
    FP: 0/1, TN issues: 0/1
    Precision: 1.000, Recall: 1.000, F1: 1.000
    ✓ PASS
[7/7] Saving to integration_test_results.yml...

Tested: 3
Passed: 3
Failed: 0
```

**What to Check:**
- Elasticsearch started successfully?
- All test payloads ingested?
- Rules detected TP cases?
- Precision ≥0.80, Recall ≥0.70?

**If Tests Fail:**
- Check query syntax (might be valid Lucene but not ES-compatible)
- Verify ECS field names match test payloads
- Check test case log entries have required fields

---

### Step 4: LLM Judge

```bash
python scripts/run_llm_judge.py \
  --rules-dir generated/detection_rules \
  --test-results integration_test_results.yml \
  --output llm_judge_report.yml \
  --project $GOOGLE_CLOUD_PROJECT
```

**Expected Output:**
```
[Judge] Evaluating: akira_ransomware_-_shadow_copy_deletion
  Quality Score: 0.92
  Precision: 1.000 (✓ PASS)
  Recall: 1.000 (✓ PASS)
  Decision: APPROVE

Total: 3
✓ Approved: 3
⚠ Needs refinement: 0
✗ Rejected: 0
```

**What to Check:**
- Judge used ACTUAL test results (not theory)?
- Approved rules have precision ≥0.80, recall ≥0.70?
- Rejected rules have actionable recommendations?

---

## Expected File Structure After Tests

```
adk-tide-generator/
├── generated/
│   ├── detection_rules/           # Final YAML rules
│   │   ├── rule1.yml
│   │   ├── rule2.yml
│   │   └── rule3.yml
│   ├── staging/                   # Temp validation files
│   │   └── json/
│   │       ├── rule1.json
│   │       ├── rule2.json
│   │       └── rule3.json
│   └── cti_context.yml
├── validation_report.yml          # Validation results
├── integration_test_results.yml   # ES test results
└── llm_judge_report.yml           # Final approval decisions
```

---

## Cleanup

```bash
./scripts/cleanup_staging.sh
```

Removes:
- `generated/staging/` folder
- Old test result files
- Mixed JSON files in detection_rules/

---

## Debugging Failed Tests

### Lucene Syntax Errors

```yaml
# validation_report.yml
step1_lucene:
  valid: false
  error: "Unexpected character '&' at position 15"
  query: "event.code:1 & process.name:cmd.exe"  # WRONG: use AND not &
  error_type: "ParseException"
```

**Fix:** Use AND, OR, NOT instead of &, |, !

### JSON Conversion Errors

```yaml
step2_conversion:
  valid: false
  error: "Missing fields: ['severity']"
```

**Fix:** Add required fields to rule YAML

### Schema Validation Errors

```yaml
step3_schema:
  valid: false
  issues:
    - "Field 'process.cmd_line' not found in ECS (did you mean 'process.command_line'?)"
  fixes_needed:
    - "Rename process.cmd_line → process.command_line"
```

**Fix:** Research correct ECS field names at elastic.co/guide/en/ecs

### Integration Test Failures

```yaml
metrics:
  rule_name:
    tp_detected: 0  # Should be 2
    precision: 0.0  # FAIL: <0.80
    recall: 0.0     # FAIL: <0.70
```

**Reasons:**
1. Query doesn't match test payload fields
2. ECS field names wrong
3. Log entry missing required fields

**Debug:**
- Check ES logs for query errors
- Verify test payload has fields from query
- Test query manually in Kibana

---

## CI/CD Integration (Future)

Once local testing passes, add to `.github/workflows/generate-detections.yml`:

```yaml
- name: Validate Rules
  run: python scripts/validate_rules.py

- name: Integration Test
  run: python scripts/integration_test_ci.py

- name: LLM Judge
  run: python scripts/run_llm_judge.py
```

---

## Success Criteria

✅ All stages complete without errors  
✅ Validation report shows all PASS  
✅ Integration tests: precision ≥0.80, recall ≥0.70  
✅ LLM judge approves at least 1 rule  
✅ Verbose logs show what's happening at each step
