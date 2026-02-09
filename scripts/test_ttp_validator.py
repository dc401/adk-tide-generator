#!/usr/bin/env python3
"""Test TTP validator with production rules"""

import asyncio
import json
import yaml
from pathlib import Path
from google import genai

#import TTP validator
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from detection_agent.tools.ttp_intent_validator import validate_all_rules

async def main():
    #load TTP validator prompt
    prompt_path = Path(__file__).parent.parent / 'detection_agent/prompts/ttp_validator_prompt.md'
    with open(prompt_path) as f:
        ttp_validator_prompt = f.read()

    #initialize Gemini client
    client = genai.Client(
        vertexai=True,
        project='your-project-id',  #will use env vars
        location='global'
    )

    #load production rules
    rules_dir = Path(__file__).parent.parent / 'production_rules'
    rules = []

    print("Loading production rules...")
    for rule_file in sorted(rules_dir.glob('*.yml')):
        with open(rule_file) as f:
            rule = yaml.safe_load(f)
        rules.append(rule)
        print(f"  ✓ {rule.get('name')}")

    print(f"\nTotal rules: {len(rules)}")
    print()

    #validate all test cases
    results = await validate_all_rules(rules, client, ttp_validator_prompt)

    #save results
    output_file = Path('ttp_validation_results.json')
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\nResults saved to: {output_file}")

    #show issues
    print("\nIssues Found:")
    for rule_result in results['rule_results']:
        for validation in rule_result['validations']:
            if validation['validation_result'] == 'INVALID':
                print(f"\n  ✗ {rule_result['rule_name']}")
                print(f"    Test: {validation['test_type']} - {validation.get('test_description', '')[:60]}...")
                print(f"    Issues: {validation.get('issues', [])}")
                print(f"    Recommendation: {validation.get('recommendations', 'N/A')}")

    return results

if __name__ == '__main__':
    asyncio.run(main())
