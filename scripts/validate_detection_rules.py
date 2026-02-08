#!/usr/bin/env python3
"""
Validate detection rules without needing Elasticsearch

Quick validation of:
- YAML structure
- Required fields
- Test case completeness
- Lucene query syntax
"""

import yaml
import sys
from pathlib import Path

try:
    from luqum.parser import parser as lucene_parser
    LUCENE_AVAILABLE = True
except ImportError:
    LUCENE_AVAILABLE = False
    print("WARNING: luqum not installed, skipping Lucene validation")


def validate_rule(rule_path: Path) -> dict:
    """validate single detection rule"""

    issues = []
    warnings = []

    #load rule
    try:
        with open(rule_path) as f:
            rule = yaml.safe_load(f)
    except Exception as e:
        return {
            'valid': False,
            'issues': [f"Failed to parse YAML: {e}"],
            'warnings': []
        }

    #required fields
    required_fields = ['name', 'description', 'type', 'query', 'language', 'severity', 'threat']
    for field in required_fields:
        if field not in rule:
            issues.append(f"Missing required field: {field}")

    #validate query
    if 'query' in rule and 'language' in rule:
        if rule['language'] == 'lucene':
            if LUCENE_AVAILABLE:
                try:
                    lucene_parser.parse(rule['query'])
                except Exception as e:
                    issues.append(f"Invalid Lucene syntax: {e}")
            else:
                warnings.append("Lucene validation skipped (luqum not installed)")

    #validate MITRE mapping
    if 'threat' in rule:
        for threat in rule['threat']:
            if 'framework' not in threat or threat['framework'] != 'MITRE ATT&CK':
                warnings.append("Threat framework not MITRE ATT&CK")

            if 'technique' not in threat or not threat['technique']:
                issues.append("No MITRE techniques mapped")

    #validate test cases
    if 'test_cases' not in rule:
        issues.append("No test cases defined")
    else:
        test_cases = rule['test_cases']
        types = [tc['type'] for tc in test_cases]

        if 'TP' not in types:
            issues.append("No True Positive (TP) test case")
        if 'TN' not in types:
            warnings.append("No True Negative (TN) test case")
        if 'FP' not in types:
            warnings.append("No False Positive (FP) test case")
        if 'FN' not in types:
            warnings.append("No False Negative (FN) test case - evasions not documented")

        #check test case structure
        for i, tc in enumerate(test_cases):
            if 'type' not in tc:
                issues.append(f"Test case {i}: missing 'type' field")
            if 'description' not in tc:
                warnings.append(f"Test case {i}: missing description")
            if 'log_entry' not in tc:
                issues.append(f"Test case {i}: missing log_entry")
            if 'expected_match' not in tc:
                issues.append(f"Test case {i}: missing expected_match")

    return {
        'valid': len(issues) == 0,
        'issues': issues,
        'warnings': warnings,
        'test_case_count': len(rule.get('test_cases', [])),
        'mitre_techniques': [
            tech['id']
            for threat in rule.get('threat', [])
            for tech in threat.get('technique', [])
        ]
    }


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--rules-dir', default='generated/detection_rules')
    args = parser.parse_args()

    rules_dir = Path(args.rules_dir)
    if not rules_dir.exists():
        print(f"ERROR: {rules_dir} not found")
        sys.exit(1)

    print("\n" + "="*80)
    print("DETECTION RULE VALIDATION")
    print("="*80 + "\n")

    rule_files = list(rules_dir.glob('*.yml'))
    if not rule_files:
        print(f"No rules found in {rules_dir}")
        sys.exit(1)

    print(f"Found {len(rule_files)} rules\n")

    all_valid = True
    results = []

    for rule_file in sorted(rule_files):
        print(f"Validating: {rule_file.name}")
        result = validate_rule(rule_file)
        results.append({'name': rule_file.name, **result})

        if result['valid']:
            print(f"  ✓ VALID")
            print(f"    Test cases: {result['test_case_count']}")
            print(f"    MITRE TTPs: {', '.join(result['mitre_techniques'])}")
        else:
            print(f"  ✗ INVALID")
            all_valid = False

        for issue in result['issues']:
            print(f"    ERROR: {issue}")

        for warning in result['warnings']:
            print(f"    WARNING: {warning}")

        print()

    #summary
    print("="*80)
    print(f"Total: {len(results)} rules")
    print(f"Valid: {sum(1 for r in results if r['valid'])}")
    print(f"Invalid: {sum(1 for r in results if not r['valid'])}")
    print("="*80)

    if not all_valid:
        sys.exit(1)


if __name__ == '__main__':
    main()
