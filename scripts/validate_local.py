#!/usr/bin/env python3
"""Local Validation (No GCP Required)

Tests stages 1-2 of validation pipeline:
- Lucene syntax validation
- YAML → JSON conversion

Useful for quick local testing before GCP validation.
"""

import json
import yaml
from pathlib import Path

try:
    from luqum.parser import parser as lucene_parser
    LUCENE_AVAILABLE = True
except ImportError:
    LUCENE_AVAILABLE = False
    print("⚠ luqum not installed - skipping Lucene syntax validation")


def validate_lucene_syntax(query: str):
    """validate lucene query syntax"""
    if not LUCENE_AVAILABLE:
        return {'valid': True, 'warning': 'luqum not available'}

    try:
        tree = lucene_parser.parse(query)
        return {
            'valid': True,
            'operators': {
                'AND': query.count(' AND '),
                'OR': query.count(' OR '),
                'NOT': query.count(' NOT '),
                'wildcards': query.count('*')
            }
        }
    except Exception as e:
        return {
            'valid': False,
            'error': str(e),
            'error_type': type(e).__name__
        }


def validate_yaml_structure(yaml_file: Path):
    """validate YAML structure and required fields"""
    try:
        with open(yaml_file) as f:
            rule_data = yaml.safe_load(f)

        #check required fields
        required = ['name', 'query', 'type', 'severity', 'risk_score']
        missing = [f for f in required if f not in rule_data]

        if missing:
            return {'valid': False, 'error': f'Missing fields: {missing}'}

        return {
            'valid': True,
            'fields_present': len(rule_data.keys()),
            'has_test_cases': 'test_cases' in rule_data
        }

    except Exception as e:
        return {'valid': False, 'error': str(e)}


def validate_rule(yaml_file: Path):
    """validate single rule locally"""

    print(f"\n{'='*80}")
    print(f"Rule: {yaml_file.stem}")
    print(f"{'='*80}")

    #load rule
    with open(yaml_file) as f:
        rule_data = yaml.safe_load(f)

    results = {'rule': yaml_file.stem, 'tests': {}}

    #test 1: YAML structure
    print("\n[1/2] YAML Structure Check...")
    yaml_result = validate_yaml_structure(yaml_file)
    results['tests']['yaml_structure'] = yaml_result

    if yaml_result['valid']:
        print(f"  ✓ PASS - {yaml_result['fields_present']} fields present")
        if yaml_result['has_test_cases']:
            print(f"  ✓ Has test cases")
    else:
        print(f"  ✗ FAIL - {yaml_result['error']}")
        return results

    #test 2: Lucene syntax
    print("\n[2/2] Lucene Syntax Check...")
    print(f"  Query: {rule_data['query'][:80]}...")

    lucene_result = validate_lucene_syntax(rule_data['query'])
    results['tests']['lucene_syntax'] = lucene_result

    if lucene_result['valid']:
        print("  ✓ PASS - Valid Lucene syntax")
        if 'operators' in lucene_result:
            ops = lucene_result['operators']
            print(f"  Operators: AND={ops['AND']}, OR={ops['OR']}, NOT={ops['NOT']}, wildcards={ops['wildcards']}")
    else:
        print(f"  ✗ FAIL - {lucene_result.get('error')}")
        print(f"  Error Type: {lucene_result.get('error_type')}")

    results['overall_pass'] = all(
        t['valid'] for t in results['tests'].values()
    )

    return results


def main():
    import sys

    rules_dir = Path('generated/detection_rules')

    if not rules_dir.exists():
        print(f"ERROR: {rules_dir} not found")
        sys.exit(1)

    print("="*80)
    print("LOCAL VALIDATION (No GCP Required)")
    print("="*80)
    print(f"\nRules Directory: {rules_dir}")

    yaml_files = list(rules_dir.glob("*.yml"))
    print(f"Found {len(yaml_files)} rules\n")

    if not yaml_files:
        print("No YAML rules found")
        sys.exit(1)

    all_results = []
    for yaml_file in yaml_files:
        result = validate_rule(yaml_file)
        all_results.append(result)

    #summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)

    passed = sum(1 for r in all_results if r['overall_pass'])
    failed = len(all_results) - passed

    print(f"\nTotal Rules: {len(all_results)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")

    if failed > 0:
        print("\nFailed Rules:")
        for r in all_results:
            if not r['overall_pass']:
                print(f"  - {r['rule']}")

    print("\nNote: This is local validation only (stages 1-2)")
    print("Run scripts/validate_rules.py with GCP for full LLM schema validation")

    return 0 if failed == 0 else 1


if __name__ == '__main__':
    import sys
    sys.exit(main())
