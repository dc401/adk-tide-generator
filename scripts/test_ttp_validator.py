#!/usr/bin/env python3
"""Test TTP validator with production rules"""

import asyncio
import json
import os
import subprocess
import yaml
from pathlib import Path
from google import genai

#import TTP validator
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from detection_agent.tools.ttp_intent_validator import validate_all_rules

async def main():
    #get rules directory from command-line argument or default to production_rules
    if len(sys.argv) > 1:
        rules_dir = Path(sys.argv[1])
    else:
        rules_dir = Path(__file__).parent.parent / 'production_rules'

    if not rules_dir.exists():
        print(f"ERROR: Rules directory not found: {rules_dir}")
        return

    #load TTP validator prompt
    prompt_path = Path(__file__).parent.parent / 'detection_agent/prompts/ttp_validator_prompt.md'
    with open(prompt_path) as f:
        ttp_validator_prompt = f.read()

    #get GCP project from env or gcloud config
    project = os.getenv('GOOGLE_CLOUD_PROJECT')
    location = os.getenv('GOOGLE_CLOUD_LOCATION', 'us-central1')

    if not project:
        try:
            project = subprocess.check_output(['gcloud', 'config', 'get-value', 'project'], text=True).strip()
        except:
            project = None

    if not project:
        print("ERROR: GCP project not configured. Set GOOGLE_CLOUD_PROJECT or run 'gcloud config set project PROJECT_ID'")
        return

    print(f"Using GCP project: {project}")
    print(f"Using location: {location}")
    print(f"Loading rules from: {rules_dir}\n")

    #initialize Gemini client
    client = genai.Client(
        vertexai=True,
        project=project,
        location=location
    )

    #load rules
    rules = []

    print("Loading detection rules...")
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
