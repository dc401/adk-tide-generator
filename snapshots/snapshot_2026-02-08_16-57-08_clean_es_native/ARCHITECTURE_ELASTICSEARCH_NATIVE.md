# Elasticsearch-Native Detection Engineering Pipeline

## Architecture Decision: Ditch Sigma

**Why?**
- Simpler: CTI → ES Detection Rules (not CTI → Sigma → pySigma → Lucene → ES)
- Faster: One conversion, one validation
- Native: Tests run in same format as generation
- ECS: Universal schema for ALL log types (cloud, network, endpoint, apps)
- Cheaper: Less LLM calls, less conversion overhead

**Readers can adapt:** Pattern works for any SIEM (Splunk, Chronicle, Sentinel)

## Pipeline Flow

```
CTI Intelligence
    ↓
[Generation Agent] → Elasticsearch Detection Rule JSON + Test Cases
    ↓
[Static Validation] → Schema check (deterministic)
    ↓
[LLM Validation] → Intent + syntax check (Gemini Pro + Google Search)
    ↓
[Integration Test] → Ingest test logs → Run query → Get matches
    ↓
[LLM Evaluation] → Judge results (require 1 TP + 1 FN, soft-fail FP/TN)
    ↓
Quality < 0.70? → [Refinement Loop] (max 2 attempts) → Re-test
    ↓
Quality ≥ 0.70? → [Stage & PR] → Human review
    ↓
Approved? → [Mock Deploy] → Production
```

## Phase 1: Generation (Gemini 2.5 Flash)

**Model:** `gemini-2.5-flash`
**Config:**
```python
temperature=0.3  # Creative but consistent
thinking_budget=6000  # Deep reasoning
tools=[GoogleSearch()]  # Ground on ES docs
```

**Output:** Elasticsearch Detection Rule
```json
{
  "name": "Akira Ransomware Shadow Copy Deletion",
  "description": "Detects deletion of shadow copies indicating ransomware pre-encryption activity",
  "type": "query",
  "query": "event.code:1 AND process.name:(*vssadmin* OR *wmic* OR *bcdedit*) AND process.command_line:(*delete*shadows* OR *shadowcopy*delete* OR *recoveryenabled*no*)",
  "language": "lucene",
  "index": ["logs-*", "winlogbeat-*", "filebeat-*"],
  "filters": [],
  "risk_score": 73,
  "severity": "high",
  "threat": [{
    "framework": "MITRE ATT&CK",
    "tactic": {"id": "TA0040", "name": "Impact"},
    "technique": [{"id": "T1490", "name": "Inhibit System Recovery"}]
  }],
  "references": [
    "https://attack.mitre.org/techniques/T1490/",
    "https://www.elastic.co/guide/en/ecs/current/ecs-process.html"
  ],
  "author": ["Detection Agent"],
  "false_positives": [
    "System administrators performing backup maintenance",
    "Legitimate software uninstallers"
  ],
  "test_cases": [
    {
      "type": "TP",
      "description": "Malicious vssadmin shadow deletion",
      "log_entry": {
        "event": {"code": 1},
        "process": {
          "name": "vssadmin.exe",
          "command_line": "vssadmin delete shadows /all /quiet",
          "executable": "C:\\Windows\\System32\\vssadmin.exe"
        },
        "@timestamp": "2024-03-12T22:15:10Z"
      },
      "expected_match": true
    },
    {
      "type": "FN",
      "description": "PowerShell evasion (alternative tool)",
      "log_entry": {
        "event": {"code": 1},
        "process": {
          "name": "powershell.exe",
          "command_line": "Get-WmiObject Win32_ShadowCopy | ForEach-Object {$_.Delete()}"
        },
        "@timestamp": "2024-03-12T22:16:00Z"
      },
      "expected_match": false,
      "evasion_note": "Uses WMI API instead of CLI tools"
    },
    {
      "type": "FP",
      "description": "Admin checking shadow copy status",
      "log_entry": {
        "event": {"code": 1},
        "process": {
          "name": "vssadmin.exe",
          "command_line": "vssadmin list shadows"
        },
        "@timestamp": "2024-03-14T10:00:00Z"
      },
      "expected_match": false
    },
    {
      "type": "TN",
      "description": "Normal system activity",
      "log_entry": {
        "event": {"code": 1},
        "process": {
          "name": "explorer.exe",
          "command_line": "C:\\Windows\\explorer.exe"
        },
        "@timestamp": "2024-03-14T10:05:00Z"
      },
      "expected_match": false
    }
  ]
}
```

**Prompt Grounding:**
```markdown
Research using Google Search:
- Elasticsearch Detection Rules structure
- ECS field mappings for your log source
- Lucene query syntax for wildcards
- Common evasion techniques for this TTP

Key URLs to reference:
- https://www.elastic.co/guide/en/security/current/detection-engine-overview.html
- https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html
- https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-query-string-query.html
```

## Phase 2: Static Validation (Deterministic)

**Script:** `scripts/validate_detection.py`

```python
def validate_detection_rule(rule_json):
    """Static JSON schema validation"""
    required_fields = ['name', 'type', 'query', 'language', 'severity']
    
    for field in required_fields:
        if field not in rule_json:
            return {"valid": False, "error": f"Missing {field}"}
    
    # Validate query syntax
    if not is_valid_lucene(rule_json['query']):
        return {"valid": False, "error": "Invalid Lucene syntax"}
    
    # Validate test cases
    if 'test_cases' not in rule_json:
        return {"valid": False, "error": "Missing test cases"}
    
    # Require at least 1 TP and 1 FN
    types = [tc['type'] for tc in rule_json['test_cases']]
    if 'TP' not in types:
        return {"valid": False, "error": "Must have at least 1 TP test case"}
    if 'FN' not in types:
        return {"valid": False, "error": "Must have at least 1 FN test case"}
    
    return {"valid": True}
```

## Phase 3: LLM Validation (Gemini 2.5 Pro)

**Model:** `gemini-2.5-pro`
**Config:**
```python
temperature=0.2  # Precise validation
thinking_budget=8000  # Deep analysis
tools=[GoogleSearch()]  # Verify fields against ECS docs
```

**Validation Prompt:**
```markdown
You are validating an Elasticsearch Detection Rule.

Rule:
{rule_json}

Validate:
1. **Query Syntax**: Is Lucene query valid?
2. **ECS Fields**: Do fields exist in ECS schema? Research via Google Search.
3. **Logic**: Does query detect the intended threat?
4. **Test Coverage**: Do test cases cover TP/FN/FP/TN scenarios?
5. **Performance**: Any slow patterns (leading wildcards, full scans)?

Research these URLs:
- ECS field reference: https://www.elastic.co/guide/en/ecs/current/ecs-{field_category}.html
- Lucene syntax: https://www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-query-string-query.html

Return JSON:
{
  "valid": true/false,
  "query_syntax_score": 0.0-1.0,
  "field_mapping_score": 0.0-1.0,
  "logic_score": 0.0-1.0,
  "test_coverage_score": 0.0-1.0,
  "overall_score": 0.0-1.0,
  "issues": ["issue1", "issue2"],
  "field_research": {
    "process.name": "✅ Valid ECS field (keyword)",
    "process.command_line": "✅ Valid ECS field (text/keyword)"
  }
}
```

## Phase 4: Integration Test

**Script:** `scripts/integration_test.py`

```python
def integration_test(rule, test_cases):
    """Run detection rule against test payloads in Elasticsearch"""
    
    # 1. Ingest test payloads
    es = Elasticsearch(['http://localhost:9200'])
    
    for test_case in test_cases:
        es.index(
            index='test-logs',
            document=test_case['log_entry'],
            id=f"{rule['name']}_{test_case['type']}"
        )
    
    es.indices.refresh(index='test-logs')
    
    # 2. Run detection query
    response = es.search(
        index='test-logs',
        query={'query_string': {'query': rule['query']}},
        size=100
    )
    
    matched_ids = [hit['_id'] for hit in response['hits']['hits']]
    
    # 3. Return raw results for LLM evaluation
    return {
        'matched_documents': response['hits']['hits'],
        'matched_ids': matched_ids,
        'expected_results': {
            tc['type']: tc['expected_match'] 
            for tc in test_cases
        }
    }
```

## Phase 5: LLM Result Evaluation (Gemini 2.5 Pro)

**Model:** `gemini-2.5-pro`
**Config:**
```python
temperature=0.1  # Very precise evaluation
thinking_budget=6000  # Analyze results
```

**Evaluation Prompt:**
```markdown
You are evaluating detection rule test results.

Detection Rule:
{rule_json}

Elasticsearch Results:
{integration_results}

Expected Behavior:
- TP cases: SHOULD match (malicious activity)
- FN cases: Should NOT match (evasion techniques we know about)
- FP cases: Should NOT match (legitimate activity) - SOFT FAIL
- TN cases: Should NOT match (normal activity) - SOFT FAIL

Actual Results:
{matched_documents}

Evaluate:
1. TP Detection: Did we catch malicious activity? (REQUIRED - must have ≥1)
2. FN Coverage: Do we document evasions? (REQUIRED - must have ≥1 bypass)
3. FP Mitigation: How many false alarms? (WARN but don't fail)
4. TN Accuracy: Do we avoid normal activity? (WARN but don't fail)

Scoring:
- TP detection: 40 points (must have ≥1 match)
- FN coverage: 30 points (must have ≥1 documented bypass)
- FP mitigation: 20 points (penalty for each FP)
- TN accuracy: 10 points (penalty for each TN match)

Quality Threshold: 0.70 to pass

Return JSON:
{
  "tp_detected": 2,
  "tp_total": 2,
  "fn_documented": 1,
  "fn_total": 1,
  "fp_count": 1,
  "tn_issues": 0,
  "quality_score": 0.85,
  "pass": true,
  "issues": [
    "1 false positive on admin checking shadow copies"
  ],
  "strengths": [
    "Catches all malicious vssadmin/wmic commands",
    "Documents PowerShell evasion technique"
  ],
  "recommendation": "APPROVE - Strong detection with minor FP risk on admin activity"
}
```

**Hard Requirements:**
- tp_detected ≥ 1 (must catch at least one attack)
- fn_documented ≥ 1 (must document at least one evasion)
- quality_score ≥ 0.70

**Soft Failures:**
- FP count (warn but don't block)
- TN issues (warn but don't block)

## Phase 6: Refinement Loop (Gemini 2.5 Flash)

**Triggered:** quality_score < 0.70
**Max Attempts:** 2

**Model:** `gemini-2.5-flash`
**Config:**
```python
temperature=0.3  # Creative problem solving
thinking_budget=5000
tools=[GoogleSearch()]
```

**Refinement Prompt:**
```markdown
Detection rule failed quality check.

Issues:
{evaluation_issues}

Failed Test Cases:
{failed_cases}

Research and fix:
1. If TP missed: Broaden query (add wildcards, alternative fields)
2. If FN not documented: Add more evasion test cases
3. If too many FPs: Add exclusion filters

Use Google Search to research:
- Alternative ECS fields
- Better Lucene patterns
- Known evasion techniques for {ttp}

Generate refined detection rule.
```

**Refinement Example:**
```
FAILED: Missed TP because query was too specific
FIX: Change process.name:"vssadmin.exe" → process.name:*vssadmin*
RETRY: Integration test → SUCCESS
```

## Phase 7: Stage & PR

**Triggered:** pass = true

1. Generate unique rule ID: `hash(rule_name + timestamp)[:8]`
2. Save to `staged_rules/{rule_id}.json`
3. Save metadata: `staged_rules/{rule_id}_metadata.json`
4. Create PR:

```yaml
Title: "Detection Rules for Review - {date}"
Body: |
  ## Detections Ready for Review
  
  {count} detection rules passed automated quality checks.
  
  ### Quality Summary
  - Overall Score: {avg_quality_score}/1.0
  - TP Detection: {tp_rate}%
  - FN Documentation: {fn_coverage}%
  - FP Rate: {fp_rate}%
  
  ### Rules
  | Name | Severity | Score | TP | FN | FP |
  |------|----------|-------|----|----|-----|
  | ... | high | 0.85 | 2/2 | 1/1 | 1 |
  
  ### Review Checklist
  - [ ] Detection logic makes sense
  - [ ] Test coverage is adequate
  - [ ] False positive risk is acceptable
  - [ ] Ready for production
```

## Phase 8: Mock Deployment

**After PR Merge:**
```yaml
jobs:
  mock-deploy:
    steps:
      - name: Deploy to Ephemeral ES
        run: |
          # Start native ES instance (via apt)
          python scripts/integration_test_ci.py \
            --rules-dir staged_rules/

          # Deploy detection rules
          python scripts/mock_deploy.py \
            --source staged_rules/ \
            --es-url http://localhost:9200
          
          # Smoke test
          python scripts/smoke_test.py
          
          # Archive
          mv staged_rules/* production_rules/
```

## Key Optimizations

### Model Selection
- **Generation:** Flash (fast, cheap, creative)
- **Validation:** Pro (accurate, grounded)
- **Evaluation:** Pro (precise, analytical)
- **Refinement:** Flash (fast iteration)

### Throttling
- Inter-agent delay: 3 seconds
- Exponential backoff: 15s, 30s, 60s
- Max retries: 3 per operation

### Exception Handling
- Quota exceeded → backoff + retry
- Timeout → reduce thinking budget
- Parse error → ask for JSON retry

### Quality Gates
- Static validation: MUST pass
- LLM validation: ≥0.75 to proceed
- Integration test: Required
- LLM evaluation: ≥0.70 to stage
- Human review: MUST approve

---

## File Structure

```
adk-elasticsearch-detector/
├── cti_src/                         # Threat intelligence
├── detection_agent/
│   ├── agent.py                     # Main orchestration
│   ├── prompts/
│   │   ├── detection_generator.md  # ES detection rule generation
│   │   ├── validator.md            # LLM validation
│   │   └── evaluator.md            # LLM result evaluation
│   └── schemas/
│       ├── detection_rule.py       # Pydantic model
│       └── test_case.py
├── generated/
│   ├── detection_rules/*.json
│   ├── tests/*.json
│   └── QUALITY_REPORT.json
├── staged_rules/                    # Passed quality gate
├── production_rules/                # Human approved
├── scripts/
│   ├── validate_detection.py       # Static validation
│   ├── integration_test.py         # ES integration test
│   ├── evaluate_results.py         # LLM evaluation
│   └── refine_detection.py         # Refinement loop
└── .github/workflows/
    └── test-detections.yml
```

This is WAY simpler than Sigma!
