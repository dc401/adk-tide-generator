#!/usr/bin/env python3
"""TTP Intent Validator - Ensures test payloads match real attack patterns"""

import json
import asyncio
from pathlib import Path
from typing import Dict, List
from google import genai
from google.genai import types

async def validate_test_payload(
    rule: Dict,
    test_case: Dict,
    client: genai.Client,
    ttp_validator_prompt: str
) -> Dict:
    """validate single test payload against real-world attack patterns"""

    #extract key information
    rule_name = rule.get('name', 'unknown')
    query = rule.get('query', '')
    test_type = test_case.get('type', 'unknown')
    description = test_case.get('description', '')
    log_entry = test_case.get('log_entry', {})
    expected_match = test_case.get('expected_match', False)
    evasion_technique = test_case.get('evasion_technique', None)

    #extract MITRE TTP
    ttps = []
    for threat in rule.get('threat', []):
        for technique in threat.get('technique', []):
            ttps.append({
                'id': technique.get('id'),
                'name': technique.get('name')
            })

    #build validation prompt
    validation_prompt = f"""{ttp_validator_prompt}

---

## Test Payload to Validate

**Rule:** {rule_name}
**Detection Query:** `{query}`
**Test Type:** {test_type}
**Description:** {description}
**Expected Match:** {expected_match}

**MITRE TTPs:**
{json.dumps(ttps, indent=2)}

**Log Entry to Validate:**
```json
{json.dumps(log_entry, indent=2)}
```

**Evasion Technique Claim** (if FN):
{evasion_technique if evasion_technique else "N/A - Not an evasion test"}

---

## Your Task

1. **Research** this TTP using Google Search:
   - MITRE ATT&CK procedure examples
   - Threat intelligence reports
   - Tool documentation
   - Real-world attack campaigns

2. **Validate** this test payload:
   - Is the command syntax correct?
   - Does it match real attack behavior?
   - Are field values realistic?
   - If FN: Would evasion actually bypass detection?

3. **Return** detailed JSON validation result with:
   - validation_result: "VALID" or "INVALID"
   - confidence: "high", "medium", or "low"
   - checks: detailed validation for each criterion
   - research_sources: URLs and citations
   - issues: any problems found
   - recommendations: how to fix if invalid

**CRITICAL:** For FN tests, simulate query execution to verify evasion claim is accurate.
"""

    try:
        #use Gemini 2.5 Pro with thinking for better reasoning
        response = await client.aio.models.generate_content(
            model='gemini-2.5-pro',
            contents=validation_prompt,
            config=types.GenerateContentConfig(
                temperature=0.0,  #deterministic for validation
                response_modalities=['TEXT'],
                thinking_config=types.ThinkingConfig(
                    mode=types.ThinkingMode.THINKING
                )
            )
        )

        response_text = response.text

        #extract JSON from response
        if '```json' in response_text:
            json_start = response_text.find('```json') + 7
            json_end = response_text.find('```', json_start)
            response_text = response_text[json_start:json_end].strip()
        elif '```' in response_text:
            json_start = response_text.find('```') + 3
            json_end = response_text.find('```', json_start)
            response_text = response_text[json_start:json_end].strip()

        result = json.loads(response_text)

        #validate result structure
        required_fields = ['validation_result', 'confidence']
        if not all(f in result for f in required_fields):
            return {
                'validation_result': 'ERROR',
                'confidence': 'low',
                'error': 'TTP validator returned incomplete result',
                'test_type': test_type,
                'rule_name': rule_name
            }

        #add test metadata
        result['test_type'] = test_type
        result['rule_name'] = rule_name
        result['test_description'] = description

        return result

    except json.JSONDecodeError as e:
        print(f"  ✗ TTP validator returned invalid JSON: {e}")
        return {
            'validation_result': 'ERROR',
            'confidence': 'low',
            'error': f'JSON parse error: {e}',
            'test_type': test_type,
            'rule_name': rule_name
        }

    except Exception as e:
        print(f"  ✗ TTP validation failed: {e}")
        return {
            'validation_result': 'ERROR',
            'confidence': 'low',
            'error': str(e),
            'test_type': test_type,
            'rule_name': rule_name
        }

async def validate_rule_test_cases(
    rule: Dict,
    client: genai.Client,
    ttp_validator_prompt: str,
    max_concurrent: int = 2
) -> Dict:
    """validate all test cases for a single rule"""

    rule_name = rule.get('name', 'unknown')
    test_cases = rule.get('test_cases', [])

    print(f"\n  Validating test cases for: {rule_name}")
    print(f"    Total test cases: {len(test_cases)}")

    results = {
        'rule_name': rule_name,
        'total_tests': len(test_cases),
        'validations': [],
        'summary': {
            'valid': 0,
            'invalid': 0,
            'errors': 0,
            'high_confidence': 0,
            'medium_confidence': 0,
            'low_confidence': 0
        }
    }

    #batch validation to avoid rate limits
    for i in range(0, len(test_cases), max_concurrent):
        batch = test_cases[i:i + max_concurrent]

        #validate batch concurrently
        tasks = [
            validate_test_payload(rule, test_case, client, ttp_validator_prompt)
            for test_case in batch
        ]
        batch_results = await asyncio.gather(*tasks)

        #store results
        for test_case, validation in zip(batch, batch_results):
            results['validations'].append(validation)

            #update summary
            if validation['validation_result'] == 'VALID':
                results['summary']['valid'] += 1
            elif validation['validation_result'] == 'INVALID':
                results['summary']['invalid'] += 1
            else:
                results['summary']['errors'] += 1

            #confidence tracking
            confidence = validation.get('confidence', 'low')
            if confidence == 'high':
                results['summary']['high_confidence'] += 1
            elif confidence == 'medium':
                results['summary']['medium_confidence'] += 1
            else:
                results['summary']['low_confidence'] += 1

            #print summary
            status_icon = "✓" if validation['validation_result'] == 'VALID' else "✗"
            print(f"    {status_icon} {test_case.get('type')} - {test_case.get('description')[:50]}... ({confidence} confidence)")

        #small delay between batches
        if i + max_concurrent < len(test_cases):
            await asyncio.sleep(3.0)

    return results

async def validate_all_rules(
    rules: List[Dict],
    client: genai.Client,
    ttp_validator_prompt: str
) -> Dict:
    """validate test cases for all rules"""

    print("="*80)
    print("TTP INTENT VALIDATION")
    print("="*80)
    print(f"Validating {len(rules)} rules...")

    all_results = {
        'total_rules': len(rules),
        'rule_results': [],
        'overall_summary': {
            'total_tests': 0,
            'valid': 0,
            'invalid': 0,
            'errors': 0,
            'high_confidence': 0,
            'medium_confidence': 0,
            'low_confidence': 0
        }
    }

    for rule in rules:
        result = await validate_rule_test_cases(rule, client, ttp_validator_prompt)
        all_results['rule_results'].append(result)

        #aggregate to overall summary
        all_results['overall_summary']['total_tests'] += result['total_tests']
        all_results['overall_summary']['valid'] += result['summary']['valid']
        all_results['overall_summary']['invalid'] += result['summary']['invalid']
        all_results['overall_summary']['errors'] += result['summary']['errors']
        all_results['overall_summary']['high_confidence'] += result['summary']['high_confidence']
        all_results['overall_summary']['medium_confidence'] += result['summary']['medium_confidence']
        all_results['overall_summary']['low_confidence'] += result['summary']['low_confidence']

    print()
    print("="*80)
    print("TTP VALIDATION COMPLETE")
    print("="*80)
    print(f"Total tests validated: {all_results['overall_summary']['total_tests']}")
    print(f"  ✓ Valid: {all_results['overall_summary']['valid']}")
    print(f"  ✗ Invalid: {all_results['overall_summary']['invalid']}")
    print(f"  ⚠️  Errors: {all_results['overall_summary']['errors']}")
    print()
    print(f"Confidence distribution:")
    print(f"  High: {all_results['overall_summary']['high_confidence']}")
    print(f"  Medium: {all_results['overall_summary']['medium_confidence']}")
    print(f"  Low: {all_results['overall_summary']['low_confidence']}")
    print("="*80)

    return all_results

if __name__ == '__main__':
    print("TTP Intent Validator - Test payloads must match real attack behavior")
    print("Run via detection agent integration")
