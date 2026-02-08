#!/usr/bin/env python3
"""
Detection Refinement Loop

Analyzes failed integration tests and automatically fixes issues:
- Field name mismatches (Sysmon → ECS conversion)
- Rule too strict (add wildcards)
- Rule too broad (add filters)

Max 2 refinement attempts per workflow run.
"""

import json
import sys
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple

from sysmon_to_ecs_mapper import convert_sysmon_to_ecs, SYSMON_TO_ECS_MAPPING

def diagnose_failure(rule_id: str, metrics: Dict, rules_dir: Path, tests_dir: Path) -> Dict:
    """Analyze why detection failed and determine fix strategy"""

    tp = metrics['tp']
    fp = metrics['fp']
    tn = metrics['tn']
    fn = metrics['fn']

    #check 1: field name mismatch (0 detections at all)
    if tp == 0 and fp == 0:
        #check if test payloads have Sysmon fields
        rule_test_dir = tests_dir / rule_id
        if not rule_test_dir.exists():
            return {
                'issue': 'no_test_payloads',
                'action': 'skip',
                'confidence': 1.0,
                'details': 'No test payloads found for this rule'
            }

        #sample first payload to check field names
        sample_file = next(rule_test_dir.glob('*.json'), None)
        if not sample_file:
            return {
                'issue': 'no_test_payloads',
                'action': 'skip',
                'confidence': 1.0,
                'details': 'No test JSON files found'
            }

        with open(sample_file) as f:
            sample = json.load(f)

        log_entry = sample.get('log_entry', sample)
        has_sysmon_fields = any(field in log_entry for field in SYSMON_TO_ECS_MAPPING.keys())
        has_ecs_fields = any('.' in field or field == '@timestamp' for field in log_entry.keys())

        if has_sysmon_fields and not has_ecs_fields:
            return {
                'issue': 'field_mismatch',
                'action': 'convert_sysmon_to_ecs',
                'confidence': 0.95,
                'details': f'Test payloads use Sysmon fields (Image, CommandLine, etc.) but Sigma rules expect ECS fields (process.name, process.command_line, etc.)',
                'sample_fields': list(log_entry.keys())[:10]
            }

    #check 2: rule too strict (high false negatives)
    if fn > tp and tp > 0:
        return {
            'issue': 'rule_too_strict',
            'action': 'broaden_rule',
            'confidence': 0.75,
            'details': f'{fn} false negatives vs {tp} true positives - rule missing attack variants'
        }

    #check 3: rule too broad (high false positives)
    if fp > tp and tp > 0:
        return {
            'issue': 'rule_too_broad',
            'action': 'add_filters',
            'confidence': 0.80,
            'details': f'{fp} false positives vs {tp} true positives - need better legitimacy filters'
        }

    #check 4: partial detection (some TP but low recall)
    if tp > 0 and (tp / (tp + fn) < 0.70):
        return {
            'issue': 'low_recall',
            'action': 'analyze_false_negatives',
            'confidence': 0.70,
            'details': f'Recall {tp/(tp+fn):.2f} - rule catching some attacks but missing others'
        }

    #unknown issue
    return {
        'issue': 'unknown',
        'action': 'manual_review',
        'confidence': 0.0,
        'details': f'Unclear failure pattern: TP={tp}, FP={fp}, TN={tn}, FN={fn}'
    }

def convert_test_payloads_to_ecs(tests_dir: Path, rule_id: str, backup_dir: Path) -> int:
    """Convert Sysmon fields to ECS in all test payloads for a rule"""

    rule_test_dir = tests_dir / rule_id
    if not rule_test_dir.exists():
        print(f"  ⚠ No test directory for {rule_id}")
        return 0

    #backup original payloads
    backup_rule_dir = backup_dir / rule_id
    backup_rule_dir.mkdir(parents=True, exist_ok=True)

    converted_count = 0

    for payload_file in rule_test_dir.glob('*.json'):
        #backup original
        shutil.copy(payload_file, backup_rule_dir / payload_file.name)

        #load and convert
        with open(payload_file) as f:
            payload = json.load(f)

        if 'log_entry' in payload:
            original_fields = set(payload['log_entry'].keys())
            payload['log_entry'] = convert_sysmon_to_ecs(payload['log_entry'])
            converted_fields = set(payload['log_entry'].keys())

            print(f"    • {payload_file.name}")
            print(f"      Before: {sorted(list(original_fields)[:5])}")
            print(f"      After: {sorted(list(converted_fields)[:5])}")

        #write converted payload
        with open(payload_file, 'w') as f:
            json.dump(payload, f, indent=2)

        converted_count += 1

    return converted_count

def main():
    import argparse

    parser = argparse.ArgumentParser(description='Refine failed detections')
    parser.add_argument('--results', default='generated/INTEGRATION_TEST_RESULTS.json',
                       help='Integration test results file')
    parser.add_argument('--rules', default='generated/sigma_rules',
                       help='Sigma rules directory')
    parser.add_argument('--tests', default='generated/tests',
                       help='Test payloads directory')
    parser.add_argument('--attempt', type=int, default=1,
                       help='Refinement attempt number (max 2)')
    parser.add_argument('--output', default='generated/REFINEMENT_REPORT.json',
                       help='Output refinement report path')
    args = parser.parse_args()

    results_path = Path(args.results)
    rules_dir = Path(args.rules)
    tests_dir = Path(args.tests)
    backup_dir = Path('generated/tests_backup')

    if not results_path.exists():
        print(f"ERROR: Results file not found: {results_path}")
        return 1

    print(f"{'='*80}")
    print(f"DETECTION REFINEMENT - ATTEMPT {args.attempt}/2")
    print(f"{'='*80}\n")

    #load test results
    with open(results_path) as f:
        results = json.load(f)

    #check if skipped
    if isinstance(results, dict) and results.get('status') == 'skipped':
        print("⚠️  Integration test was skipped - nothing to refine")
        return 0

    #analyze each failed rule
    refinements = []
    total_fixed = 0

    for rule_id, metrics in results.items():
        f1_score = metrics['f1_score']

        if f1_score >= 0.75:
            print(f"✓ {metrics['rule_title']}: F1={f1_score:.2f} (PASS)\n")
            continue

        print(f"⚠ {metrics['rule_title']}: F1={f1_score:.2f} (FAIL)")
        print(f"  TP={metrics['tp']}, FP={metrics['fp']}, TN={metrics['tn']}, FN={metrics['fn']}\n")

        #diagnose failure
        diagnosis = diagnose_failure(rule_id, metrics, rules_dir, tests_dir)

        print(f"  Diagnosis: {diagnosis['issue']}")
        print(f"  Action: {diagnosis['action']}")
        print(f"  Confidence: {diagnosis['confidence']:.0%}")
        print(f"  Details: {diagnosis['details']}\n")

        #apply fix
        if diagnosis['action'] == 'convert_sysmon_to_ecs':
            print(f"  Fixing: Converting Sysmon → ECS fields...")

            #backup and convert
            converted = convert_test_payloads_to_ecs(tests_dir, rule_id, backup_dir)

            print(f"  ✓ Converted {converted} test payloads\n")
            total_fixed += 1

            refinements.append({
                'rule_id': rule_id,
                'rule_title': metrics['rule_title'],
                'issue': diagnosis['issue'],
                'action': diagnosis['action'],
                'confidence': diagnosis['confidence'],
                'payloads_modified': converted,
                'timestamp': datetime.now().isoformat()
            })

        elif diagnosis['action'] == 'skip':
            print(f"  Skipping: {diagnosis['details']}\n")

        else:
            print(f"  ⚠ Action '{diagnosis['action']}' not yet implemented\n")

    #save refinement report
    report = {
        'attempt': args.attempt,
        'timestamp': datetime.now().isoformat(),
        'total_rules_refined': total_fixed,
        'refinements': refinements,
        'backup_location': str(backup_dir)
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(exist_ok=True, parents=True)
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"{'='*80}")
    print(f"REFINEMENT SUMMARY")
    print(f"{'='*80}")
    print(f"  Rules refined: {total_fixed}")
    print(f"  Backup location: {backup_dir}")
    print(f"  Report saved: {output_path}\n")

    if total_fixed > 0:
        print("✓ Re-run integration tests to validate fixes")
        return 0
    else:
        print("⚠ No fixes applied - manual review needed")
        return 1

if __name__ == '__main__':
    sys.exit(main())
