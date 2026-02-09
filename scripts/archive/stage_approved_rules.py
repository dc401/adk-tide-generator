#!/usr/bin/env python3
"""
Stage approved rules for human review

Moves rules that passed LLM judge to staged_rules/ with unique UIDs
"""

import argparse
import yaml
import shutil
import hashlib
import time
from pathlib import Path
from datetime import datetime


def generate_rule_uid(rule_name: str) -> str:
    """generate short UID for uniqueness"""
    hash_obj = hashlib.sha256(rule_name.encode())
    return hash_obj.hexdigest()[:8]


def stage_approved_rules(judge_report_path: Path, rules_dir: Path, output_dir: Path):
    """stage rules that passed LLM judge"""

    #load judge report
    with open(judge_report_path) as f:
        report = yaml.safe_load(f)

    evaluations = report.get('evaluations', [])
    approved = [e for e in evaluations if e['deployment_decision'] in ['APPROVE', 'CONDITIONAL']]

    if not approved:
        print("No rules approved for staging")
        return 0

    #create staged_rules directory
    output_dir.mkdir(exist_ok=True)
    (output_dir / 'tests').mkdir(exist_ok=True)

    batch_id = f"batch_{int(time.time())}"
    staged_count = 0

    for evaluation in approved:
        rule_name = evaluation['rule_name']
        rule_file = rules_dir / f"{rule_name}.yml"

        if not rule_file.exists():
            print(f"WARNING: Rule file not found: {rule_file}")
            continue

        #generate unique filename
        uid = generate_rule_uid(rule_name)
        staged_filename = f"{rule_name}_{uid}.yml"

        #copy rule with UID
        shutil.copy(rule_file, output_dir / staged_filename)

        #write metadata
        metadata = {
            'rule_name': rule_name,
            'uid': uid,
            'batch_id': batch_id,
            'timestamp': datetime.now().isoformat(),
            'quality_score': evaluation['quality_score'],
            'deployment_decision': evaluation['deployment_decision'],
            'evaluation': evaluation['evaluation'],
            'reasoning': evaluation['reasoning']
        }

        metadata_file = output_dir / f"{rule_name}_{uid}_metadata.json"
        import json
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)

        print(f"Staged: {rule_name} → {staged_filename}")
        staged_count += 1

    print(f"\nStaged {staged_count} rules")
    print(f"Batch ID: {batch_id}")

    return staged_count


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--judge-report', required=True, help='LLM judge report YAML')
    parser.add_argument('--rules-dir', required=True, help='Detection rules directory')
    parser.add_argument('--output-dir', default='staged_rules', help='Output directory')

    args = parser.parse_args()

    count = stage_approved_rules(
        Path(args.judge_report),
        Path(args.rules_dir),
        Path(args.output_dir)
    )

    if count == 0:
        exit(1)


if __name__ == '__main__':
    main()
