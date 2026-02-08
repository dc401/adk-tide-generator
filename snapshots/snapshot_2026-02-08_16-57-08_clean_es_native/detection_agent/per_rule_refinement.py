"""Per-rule smart refinement with feedback loops

Refines individual rules at each validation stage, not just pipeline-level retries
"""

import asyncio
import yaml
from pathlib import Path
from typing import Dict, Optional

from google import genai
from google.genai import types


async def refine_rule_with_feedback(
    client,
    original_rule: Dict,
    feedback: Dict,
    refinement_type: str,
    cti_content: str,
    prompts: Dict,
    max_attempts: int = 2
) -> Optional[Dict]:
    """refine a single rule based on stage-specific feedback
    
    refinement_type:
    - 'validation' - failed Lucene/JSON/schema checks
    - 'integration' - failed precision/recall thresholds
    - 'judge' - LLM judge recommended refinement
    """
    
    print(f"  🔧 Refining rule: {original_rule['name']}")
    print(f"     Type: {refinement_type}")
    
    #build refinement prompt based on failure type
    if refinement_type == 'validation':
        refinement_prompt = f"""## Rule Refinement - Validation Failures

**Original Rule:**
```yaml
{yaml.dump(original_rule, default_flow_style=False, sort_keys=False)}
```

**Validation Failures:**
{yaml.dump(feedback, default_flow_style=False, sort_keys=False)}

**Your Task:**
Fix the validation errors and regenerate the rule.

Common fixes:
- Lucene syntax errors: Check operators (AND, OR, NOT), field:value format
- Missing fields: Add required schema fields (severity, risk_score, etc.)
- Invalid ECS fields: Research correct field names at elastic.co/guide/en/ecs
- MITRE references: Verify TTP IDs at attack.mitre.org

Return the FIXED rule in the same format.
"""

    elif refinement_type == 'integration':
        refinement_prompt = f"""## Rule Refinement - Integration Test Failures

**Original Rule:**
```yaml
{yaml.dump(original_rule, default_flow_style=False, sort_keys=False)}
```

**Test Results:**
{yaml.dump(feedback, default_flow_style=False, sort_keys=False)}

**Analysis:**
- Precision: {feedback.get('precision', 0):.3f} (threshold ≥0.80)
- Recall: {feedback.get('recall', 0):.3f} (threshold ≥0.70)
- TP detected: {feedback.get('tp_detected', 0)}/{feedback.get('tp_total', 0)}
- FP triggered: {feedback.get('fp_triggered', 0)}/{feedback.get('fp_total', 0)}

**Your Task:**
Analyze whether the RULE or TEST CASES need refinement:

**If Precision is low (<0.80):**
- Rule is too broad (catching benign activity)
- Add filters to exclude false positives
- Tighten query specificity

**If Recall is low (<0.70):**
- Rule is too narrow (missing malicious activity)
- Broaden query to catch more variants
- Add OR clauses for alternative attack patterns

**If Test cases are wrong:**
- TP cases should represent ACTUAL malicious behavior
- FP cases should represent REALISTIC benign activity
- Ensure test log entries match ECS schema

Return either:
1. FIXED rule with better query
2. FIXED test cases with corrected log entries
3. BOTH if needed

Make sure to preserve the original detection intent from CTI.
"""

    elif refinement_type == 'judge':
        refinement_prompt = f"""## Rule Refinement - LLM Judge Recommendations

**Original Rule:**
```yaml
{yaml.dump(original_rule, default_flow_style=False, sort_keys=False)}
```

**Judge Feedback:**
{yaml.dump(feedback, default_flow_style=False, sort_keys=False)}

**Judge Recommendation:** {feedback.get('recommendation', 'REFINE')}
**Issues Identified:**
{yaml.dump(feedback.get('issues', []), default_flow_style=False)}

**Specific Fixes Needed:**
{yaml.dump(feedback.get('recommendations', []), default_flow_style=False)}

**Your Task:**
Follow the judge's recommendations and regenerate the rule.

The judge has evaluated this rule against ACTUAL integration test results.
Apply the specific fixes suggested.

Return the REFINED rule addressing all issues.
"""

    else:
        raise ValueError(f"Unknown refinement type: {refinement_type}")
    
    #call LLM to refine
    for attempt in range(max_attempts):
        print(f"     Attempt {attempt + 1}/{max_attempts}...")
        
        try:
            config = types.GenerateContentConfig(
                temperature=0.3,  #higher than validation (more creative fixes)
                system_instruction="You are a detection engineer fixing broken rules. Research and validate your fixes."
            )
            
            response = client.models.generate_content(
                model='gemini-2.5-flash',
                contents=refinement_prompt,
                config=config
            )
            
            #parse refined rule
            refined_yaml = response.text
            
            #extract YAML from markdown if needed
            if '```yaml' in refined_yaml:
                start = refined_yaml.find('```yaml') + 7
                end = refined_yaml.find('```', start)
                refined_yaml = refined_yaml[start:end].strip()
            elif '```' in refined_yaml:
                start = refined_yaml.find('```') + 3
                end = refined_yaml.find('```', start)
                refined_yaml = refined_yaml[start:end].strip()
            
            refined_rule = yaml.safe_load(refined_yaml)
            
            print(f"     ✓ Refinement successful")
            return refined_rule
        
        except Exception as e:
            print(f"     ✗ Refinement attempt {attempt + 1} failed: {e}")
            if attempt == max_attempts - 1:
                print(f"     Giving up on refinement")
                return None
            await asyncio.sleep(2.0)
    
    return None


async def should_refine_query_or_tests(
    rule: Dict,
    test_metrics: Dict,
    client
) -> str:
    """smart decision: does the QUERY need fixing or the TEST CASES?
    
    Returns: 'query', 'tests', or 'both'
    """
    
    #build analysis prompt
    analysis_prompt = f"""You are a detection engineering expert analyzing test failures.

**Rule Query:**
```
{rule['query']}
```

**Test Metrics:**
- Precision: {test_metrics.get('precision', 0):.3f}
- Recall: {test_metrics.get('recall', 0):.3f}
- TP detected: {test_metrics.get('tp_detected', 0)}/{test_metrics.get('tp_total', 0)}
- FP triggered: {test_metrics.get('fp_triggered', 0)}/{test_metrics.get('fp_total', 0)}
- TN wrongly triggered: {test_metrics.get('tn_triggered', 0)}/{test_metrics.get('tn_total', 0)}

**Test Cases:**
{yaml.dump(rule.get('test_cases', []), default_flow_style=False)}

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
    
    config = types.GenerateContentConfig(temperature=0.1)
    
    response = client.models.generate_content(
        model='gemini-2.5-flash',
        contents=analysis_prompt,
        config=config
    )
    
    #parse decision
    try:
        if '```yaml' in response.text:
            start = response.text.find('```yaml') + 7
            end = response.text.find('```', start)
            decision_yaml = response.text[start:end].strip()
        else:
            decision_yaml = response.text
        
        decision = yaml.safe_load(decision_yaml)
        return decision.get('needs_fixing', 'query')
    
    except Exception:
        #default to query refinement
        return 'query'
