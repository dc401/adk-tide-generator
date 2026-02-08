# Multi-Level Smart Refinement Implementation

## Overview

Implemented comprehensive per-rule smart refinement at **three validation stages**, enabling automatic rule improvement without regenerating the entire pipeline.

## Architecture

```
CTI Files → Detection Agent → Rules Generated
                                      ↓
         ┌────────────────────────────┴─────────────────────────────┐
         │                                                           │
    STAGE 1: Validation                                         STAGE 1
    ├─ Lucene syntax check                                      Refinement
    ├─ YAML → JSON conversion                                   ↓
    ├─ LLM schema validator                                     Fix syntax,
    └─ ✗ Fails → Refine rule (max 2 attempts)                  ECS fields,
         │                                                      MITRE refs
         ↓
    STAGE 2: Integration Testing                               STAGE 2
    ├─ Deploy to Elasticsearch                                 Refinement
    ├─ Ingest TP/FN/FP/TN payloads                            ↓
    ├─ Execute queries                                         Smart decision:
    ├─ Calculate precision/recall                              - Refine QUERY
    └─ ✗ Fails (<0.80 precision/<0.70 recall)                  - OR refine TESTS
         → Smart decision: Fix query OR test cases
         → Refine (max 2 attempts)
         │
         ↓
    STAGE 3: LLM Judge                                         STAGE 3
    ├─ Empirical evaluation                                    Refinement
    ├─ Quality scoring                                         ↓
    ├─ Deployment recommendation                               Follow judge's
    └─ Decision: REFINE                                        specific
         → Refine based on judge feedback (max 2 attempts)     recommendations
         │
         ↓
    APPROVED RULES → Human Review → Production
```

## Key Innovation: Granular vs. Pipeline-Level Refinement

**Previous approach (pipeline-level):**
- If 0 rules pass, regenerate EVERYTHING
- Wastes time if only one rule needs fixing
- Max 3 iterations at pipeline level

**New approach (per-rule refinement):**
- Each rule gets refined at the stage where it fails
- Failed validation? Fix syntax/schema issues only
- Failed integration test? Smart decision - fix query OR test cases
- Judge says REFINE? Follow specific recommendations
- **Result:** Faster convergence, more targeted fixes

## Implementation Details

### 1. Validation Stage Refinement

**File:** `scripts/validate_rules.py`

**Function:** `validate_with_refinement()`

**Triggers:**
- Lucene syntax errors
- JSON conversion failures
- LLM schema validation failures

**Refinement Strategy:**
```python
async def validate_with_refinement(yaml_file, staging_dir, client, max_refinement_attempts=2):
    for refinement_iteration in range(max_refinement_attempts + 1):
        result = await validate_rule_pipeline(current_rule_path, staging_dir, client)

        if result['overall_pass']:
            if refinement_iteration > 0:
                #save refined rule back to original location
                save_refined_rule(current_rule_path, original_file)
            return result

        #refine based on validation feedback
        refined_rule = await refine_rule_with_feedback(
            client=client,
            original_rule=current_rule,
            feedback=feedback,
            refinement_type='validation',
            max_attempts=2
        )

        current_rule_path = save_temp_refined_rule(refined_rule)
```

**Fixes Applied:**
- Lucene syntax: Check AND/OR/NOT operators, field:value format
- Missing fields: Add required schema fields (severity, risk_score, etc.)
- Invalid ECS fields: Research correct names at elastic.co/guide/en/ecs
- MITRE references: Verify TTP IDs at attack.mitre.org

### 2. Integration Test Stage Refinement

**File:** `scripts/integration_test_ci.py`

**Function:** `test_single_rule_with_refinement()`

**Triggers:**
- Precision < 0.80 (too many false positives)
- Recall < 0.70 (missing attacks)

**Smart Decision Logic:**
```python
async def test_single_rule_with_refinement(rule_file, es_client, index_name, gemini_client):
    for refinement_iteration in range(max_refinement_attempts + 1):
        #test rule
        metrics = calculate_metrics(test_results)

        if metrics['pass_threshold']:  #precision ≥0.80 AND recall ≥0.70
            return success

        #smart decision: fix query OR test cases?
        fix_target = await should_refine_query_or_tests(rule_data, metrics, gemini_client)

        if fix_target == 'query':
            #query is too broad (low precision) or too narrow (low recall)
            refined_rule = await refine_rule_with_feedback(
                refinement_type='integration',
                feedback={
                    'precision': metrics['precision'],
                    'recall': metrics['recall'],
                    'tp_detected': metrics['tp_detected'],
                    'fp_triggered': metrics['fp_triggered']
                }
            )
        elif fix_target == 'tests':
            #test cases have wrong expected behavior
            refined_rule = await refine_test_cases(...)

        #retest refined rule
        current_rule_path = save_temp_refined_rule(refined_rule)
```

**Smart Decision Criteria:**
- **Fix query if:**
  - TP cases didn't match → Query too specific
  - FP cases matched → Query too broad
  - Query has obvious logic errors

- **Fix test cases if:**
  - TP test logs don't match actual attack patterns
  - FP test logs are unrealistic
  - ECS field values in test logs are wrong

### 3. LLM Judge Stage Refinement

**File:** `scripts/run_llm_judge.py`

**Function:** `evaluate_rule_with_refinement()`

**Triggers:**
- Judge decision: REFINE (not APPROVE or REJECT)
- Quality score calculated from actual integration test results

**Refinement Strategy:**
```python
async def evaluate_rule_with_refinement(client, rule_file, rule_data, test_metrics):
    for refinement_iteration in range(max_refinement_attempts + 1):
        #evaluate rule based on actual test results
        evaluation = await evaluate_rule_with_actual_results(
            client, rule_data, test_metrics
        )

        if evaluation['deployment_decision'] == 'APPROVE':
            return success

        if evaluation['deployment_decision'] == 'REJECT':
            return rejection

        #REFINE decision - follow judge's specific recommendations
        refined_rule = await refine_rule_with_feedback(
            refinement_type='judge',
            feedback={
                'quality_score': evaluation['quality_score'],
                'issues': evaluation['precision_assessment']['issues'] +
                         evaluation['recall_assessment']['issues'],
                'recommendations': evaluation['recommendations']
            }
        )

        #re-evaluate refined rule
        current_rule = refined_rule
```

**Judge Feedback Example:**
```yaml
deployment_decision: REFINE
quality_score: 0.68
precision_assessment:
  score: 0.67
  pass: false
  issues:
    - "Query matches benign service account delegation"
    - "Filter excludes .gserviceaccount.com but should check delegation context"
recall_assessment:
  score: 0.75
  pass: true
  issues: []
recommendations:
  - "Add filter for protoPayload.request.delegateServiceAccountEmail check"
  - "Require protoPayload.authenticationInfo.principalEmail NOT endswith @yourcompany.com"
```

## Core Refinement Engine

**File:** `detection_agent/per_rule_refinement.py`

### Function: `refine_rule_with_feedback()`

**Inputs:**
- `original_rule`: Current rule YAML
- `feedback`: Stage-specific failure details
- `refinement_type`: 'validation', 'integration', or 'judge'
- `cti_content`: Original CTI (if needed for context)
- `max_attempts`: Max LLM refinement attempts (default 2)

**Output:**
- Refined rule YAML (or None if refinement fails)

**Prompts by Refinement Type:**

1. **Validation refinement:**
```markdown
## Rule Refinement - Validation Failures

**Original Rule:**
[YAML]

**Validation Failures:**
- Lucene syntax error at position X
- Missing required field: severity
- Invalid ECS field: process.cmdline (should be process.command_line)

**Your Task:**
Fix the validation errors and regenerate the rule.

Common fixes:
- Lucene syntax errors: Check operators (AND, OR, NOT), field:value format
- Missing fields: Add required schema fields (severity, risk_score, etc.)
- Invalid ECS fields: Research correct field names at elastic.co/guide/en/ecs
- MITRE references: Verify TTP IDs at attack.mitre.org

Return the FIXED rule in the same format.
```

2. **Integration test refinement:**
```markdown
## Rule Refinement - Integration Test Failures

**Original Rule:**
[YAML]

**Test Results:**
- Precision: 0.67 (threshold ≥0.80)
- Recall: 0.75 (threshold ≥0.70)
- TP detected: 2/3
- FP triggered: 1/2

**Analysis:**
If Precision is low (<0.80):
- Rule is too broad (catching benign activity)
- Add filters to exclude false positives
- Tighten query specificity

If Recall is low (<0.70):
- Rule is too narrow (missing malicious activity)
- Broaden query to catch more variants
- Add OR clauses for alternative attack patterns

**Your Task:**
Analyze whether the RULE or TEST CASES need refinement.

Return either:
1. FIXED rule with better query
2. FIXED test cases with corrected log entries
3. BOTH if needed

Make sure to preserve the original detection intent from CTI.
```

3. **Judge refinement:**
```markdown
## Rule Refinement - LLM Judge Recommendations

**Original Rule:**
[YAML]

**Judge Feedback:**
- Quality Score: 0.68 (threshold ≥0.70)
- Recommendation: REFINE
- Issues: [list of specific problems]
- Specific Fixes: [actionable recommendations]

**Your Task:**
Follow the judge's recommendations and regenerate the rule.

The judge has evaluated this rule against ACTUAL integration test results.
Apply the specific fixes suggested.

Return the REFINED rule addressing all issues.
```

### Function: `should_refine_query_or_tests()`

**Purpose:** Smart decision - does the QUERY need fixing or the TEST CASES?

**Returns:** 'query', 'tests', or 'both'

**Decision Logic:**
```python
async def should_refine_query_or_tests(rule, test_metrics, client):
    analysis_prompt = f"""
**Rule Query:**
{rule['query']}

**Test Metrics:**
- Precision: {test_metrics['precision']:.3f}
- Recall: {test_metrics['recall']:.3f}
- TP detected: {test_metrics['tp_detected']}/{test_metrics['tp_total']}
- FP triggered: {test_metrics['fp_triggered']}/{test_metrics['fp_total']}

**Test Cases:**
{yaml.dump(rule.get('test_cases', []))}

**Your Task:**
Determine what needs to be fixed.

Return YAML:
```yaml
needs_fixing: query | tests | both
reasoning: explain why
specific_issue: what exactly is wrong
```

**Decision Logic:**
- If TP cases didn't match: Query might be too specific OR test cases have wrong field values
- If FP cases matched: Query is too broad OR FP test cases are unrealistic
- If TN cases matched: Query has logic error OR TN test cases duplicate TP scenarios

Be specific about what's broken.
"""

    response = client.models.generate_content(analysis_prompt)
    decision = yaml.safe_load(response.text)
    return decision['needs_fixing']
```

## Usage

### Validation with Refinement
```bash
python scripts/validate_rules.py \
  --rules-dir generated/detection_rules \
  --staging-dir generated/staging \
  --project YOUR_GCP_PROJECT
```

Output:
```
[Validate] akira_ransomware_shadow_copy_deletion
  [1/3] Lucene syntax check...
    ✗ FAIL: Unexpected token at position 42
  🔄 Refinement iteration 1/2
    Retrying validation...
  [1/3] Lucene syntax check...
    ✓ PASS
  [2/3] YAML → JSON conversion...
    ✓ PASS
  [3/3] LLM schema validation...
    ✓ PASS
  ✓ Rule passed after 1 refinement(s)
```

### Integration Testing with Refinement
```bash
python scripts/integration_test_ci.py \
  --rules-dir generated/detection_rules \
  --project YOUR_GCP_PROJECT \
  --skip-install  #if ES already running
```

Output:
```
[5/7] Executing detection rules with refinement...

  akira_ransomware_shadow_copy_deletion
    TP: 2/3, FN: 0/1
    FP: 1/2, TN issues: 0/2
    Precision: 0.667, Recall: 0.667, F1: 0.667
    ✗ FAIL (below 0.80 precision threshold)

  🔄 Refinement iteration 1/2
    Analyzing what needs fixing...
    Decision: Fix query
    Refining based on integration feedback...
    Retesting refined rule...
    TP: 3/3, FN: 0/1
    FP: 0/2, TN issues: 0/2
    Precision: 1.000, Recall: 1.000, F1: 1.000
    ✓ PASS after 1 refinement(s)
```

### LLM Judge with Refinement
```bash
python scripts/run_llm_judge.py \
  --rules-dir generated/detection_rules \
  --test-results integration_test_results.yml \
  --project YOUR_GCP_PROJECT
```

Output:
```
[Judge] Evaluating: akira_ransomware_shadow_copy_deletion
  Quality Score: 0.68
  Precision: 0.800 (✓ PASS)
  Recall: 0.670 (✗ FAIL)
  Decision: REFINE

  🔄 Judge refinement iteration 1/2
  Refining based on judge feedback...
  Re-evaluating refined rule...
  Quality Score: 0.82
  Precision: 0.900 (✓ PASS)
  Recall: 0.750 (✓ PASS)
  Decision: APPROVE
  ✓ Approved after 1 refinement(s)
```

### Disable Refinement (for testing)
```bash
#disable at any stage
python scripts/validate_rules.py --no-refinement
python scripts/integration_test_ci.py --no-refinement
python scripts/run_llm_judge.py --no-refinement
```

## Benefits

### 1. Faster Convergence
- **Before:** Regenerate 5 rules if one fails → ~10 min
- **After:** Refine the one failed rule → ~2 min

### 2. More Targeted Fixes
- Validation failures get syntax fixes (not content changes)
- Integration failures get query OR test adjustments (not both)
- Judge feedback targets specific issues (not generic improvements)

### 3. Preserves Working Rules
- Don't regenerate rules that already passed
- Only modify rules that failed specific checks
- Keep original CTI intent while fixing technical issues

### 4. Clear Failure Attribution
- Know EXACTLY which stage failed
- Know EXACTLY what needs fixing
- Track refinement iterations per stage

## Metrics

### Refinement Success Rates (Expected)
- Validation refinement: ~80% success after 1 attempt
- Integration test refinement: ~60% success after 1 attempt
- Judge refinement: ~70% success after 1 attempt

### Token Consumption
- Validation refinement: ~2,000 tokens per attempt (Flash)
- Integration refinement: ~3,000 tokens per attempt (Flash, includes smart decision)
- Judge refinement: ~2,500 tokens per attempt (Pro)

### Time Savings
- Validation refinement: 30s per rule (vs. 5 min full regeneration)
- Integration refinement: 2 min per rule (vs. 10 min full test cycle)
- Judge refinement: 1 min per rule (vs. re-running integration tests)

## Testing Plan

### Unit Tests (validation refinement)
```bash
#test with intentionally broken rule
cat > generated/detection_rules/broken_rule.yml <<EOF
name: Test Broken Rule
query: "invalid syntax AND ( no closing paren"
type: query
severity: high
risk_score: 75
EOF

python scripts/validate_rules.py --rules-dir generated/detection_rules
#should auto-fix syntax and pass
```

### Integration Tests (query/test refinement)
```bash
#test with rule that has low precision
#add FP test case that should NOT alert but does

python scripts/integration_test_ci.py --rules-dir generated/detection_rules
#should detect low precision, refine query, and retest
```

### End-to-End Test (all stages)
```bash
#test complete pipeline with real CTI
python run_agent.py --cti-folder cti_src --output generated/
python scripts/validate_rules.py --rules-dir generated/detection_rules
python scripts/integration_test_ci.py --rules-dir generated/detection_rules
python scripts/run_llm_judge.py --rules-dir generated/detection_rules

#all stages should refine automatically if failures occur
```

## Future Enhancements

### 1. Refinement Analytics
- Track which refinement types are most effective
- Measure average refinement attempts per rule
- Identify patterns in common failures

### 2. Learning from Refinements
- Store successful refinement strategies
- Use as few-shot examples for future refinements
- Build refinement pattern library

### 3. Cross-Stage Refinement
- If judge says REFINE, optionally re-run integration test
- If integration test refined, optionally re-validate
- Ensure consistency across all stages

## Conclusion

Multi-level smart refinement enables:
- **Faster iteration** - Fix specific issues, not everything
- **Better quality** - Targeted fixes preserve working rules
- **Lower cost** - Fewer LLM calls than full regeneration
- **Clear debugging** - Know exactly what failed and why

This brings the detection pipeline closer to production-ready autonomous operation while maintaining human oversight through the final approval gate.
