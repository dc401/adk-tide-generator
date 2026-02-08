#!/usr/bin/env python3
"""
Static LLM Judge: Pre-filter detection rules BEFORE integration testing

Evaluates rule quality based on:
- TTP alignment with CTI
- Detection logic soundness
- False positive risk assessment
- Test scenario coverage

Does NOT require integration test results - evaluates rules statically.
"""

import json
import yaml
import sys
import os
from pathlib import Path
from typing import Dict, List
from datetime import datetime

try:
    import vertexai
    from vertexai.generative_models import GenerativeModel
except ImportError:
    print("ERROR: google-cloud-aiplatform library not installed")
    print("Run: pip install google-cloud-aiplatform")
    sys.exit(1)

STATIC_JUDGE_PROMPT = """You are a detection engineering expert evaluating Sigma detection rules.

Evaluate the rule based on these criteria (NO integration test results available):

1. **TTP Alignment** (0.0-1.0): Does detection logic actually detect the mapped MITRE technique?
2. **Detection Logic Quality** (0.0-1.0): Is the logic sound, not too broad, not too narrow?
3. **False Positive Risk** (LOW/MEDIUM/HIGH): Based on detection fields and filters
4. **Test Scenario Coverage** (0.0-1.0): Are TP/FN/FP/TN scenarios comprehensive?
5. **Deployment Readiness** (0.0-1.0): Is this rule production-ready as-is?

Output as JSON:
{
  "rule_id": "<rule UUID>",
  "rule_title": "<rule title>",
  "ttp_alignment_score": 0.85,
  "detection_logic_score": 0.90,
  "false_positive_risk": "MEDIUM",
  "test_coverage_score": 0.80,
  "deployment_readiness_score": 0.82,
  "overall_quality_score": 0.84,
  "deployment_decision": "APPROVE|CONDITIONAL|REJECT",
  "strengths": ["strength 1", "strength 2"],
  "weaknesses": ["weakness 1", "weakness 2"],
  "recommendations": ["fix 1", "fix 2"]
}

Decision criteria:
- APPROVE: overall_quality_score >= 0.80, fp_risk LOW, deployment_readiness >= 0.80
- CONDITIONAL: overall_quality_score >= 0.65, needs minor improvements
- REJECT: overall_quality_score < 0.65 or critical flaws

Be strict - only APPROVE truly production-ready rules.
"""

def load_sigma_rules(rules_dir: Path) -> Dict:
    """load all sigma rules from directory"""
    rules = {}

    rule_files = list(rules_dir.glob('*.yml')) + list(rules_dir.glob('*.yaml'))

    for rule_file in rule_files:
        with open(rule_file) as f:
            rule_yaml = yaml.safe_load(f)

        rule_id = rule_yaml.get('id')
        if rule_id:
            rules[str(rule_id)] = {
                'yaml': rule_yaml,
                'file': rule_file.name
            }

    return rules

def load_test_payloads(tests_dir: Path) -> Dict:
    """load test payload metadata for all rules"""
    test_metadata = {}

    if not tests_dir.exists():
        return test_metadata

    for rule_dir in tests_dir.iterdir():
        if not rule_dir.is_dir():
            continue

        #extract rule ID from directory name (assumes format: <rule_name>_<8char_id>)
        rule_id_prefix = rule_dir.name.split('_')[-1] if '_' in rule_dir.name else ''

        scenarios = {}
        for scenario_type in ['true_positive', 'false_negative', 'false_positive', 'true_negative']:
            payload_files = list(rule_dir.glob(f"{scenario_type}_*.json"))

            if payload_files:
                #load first payload for description
                with open(payload_files[0]) as f:
                    payload = json.load(f)

                scenarios[scenario_type] = {
                    'count': len(payload_files),
                    'description': payload.get('_description', ''),
                    'sample': payload
                }

        if scenarios:
            test_metadata[rule_id_prefix] = scenarios

    return test_metadata

def evaluate_rule_static(rule_id: str, rule_data: Dict, test_scenarios: Dict, model) -> Dict:
    """evaluate rule statically (no integration test results)"""

    rule = rule_data['yaml']

    #prepare evaluation input
    eval_input = {
        'rule_id': rule_id,
        'rule': {
            'title': rule.get('title'),
            'description': rule.get('description'),
            'level': rule.get('level'),
            'tags': rule.get('tags', []),
            'logsource': rule.get('logsource'),
            'detection': rule.get('detection'),
            'falsepositives': rule.get('falsepositives', []),
            'test_scenarios': rule.get('test_scenarios', {})
        },
        'test_payloads_available': test_scenarios
    }

    prompt = f"""{STATIC_JUDGE_PROMPT}

Evaluate this Sigma detection rule:

{json.dumps(eval_input, indent=2)}

Provide evaluation in JSON format as specified above."""

    print(f"  Evaluating: {rule.get('title', 'Unknown')[:60]}...")

    try:
        response = model.generate_content(prompt)
        response_text = response.text

        #extract JSON
        if '```json' in response_text:
            json_start = response_text.find('```json') + 7
            json_end = response_text.find('```', json_start)
            json_text = response_text[json_start:json_end].strip()
        elif '```' in response_text:
            json_start = response_text.find('```') + 3
            json_end = response_text.find('```', json_start)
            json_text = response_text[json_start:json_end].strip()
        else:
            json_text = response_text.strip()

        evaluation = json.loads(json_text)
        evaluation['rule_file'] = rule_data['file']

        return evaluation

    except json.JSONDecodeError as e:
        print(f"    ⚠ Warning: Could not parse JSON response")
        print(f"    Error: {e}")

        return {
            'rule_id': rule_id,
            'rule_title': rule.get('title'),
            'rule_file': rule_data['file'],
            'deployment_decision': 'REJECT',
            'overall_quality_score': 0.0,
            'error': 'Failed to parse LLM response'
        }

    except Exception as e:
        print(f"    ✗ Error: {e}")
        return {
            'rule_id': rule_id,
            'rule_title': rule.get('title'),
            'rule_file': rule_data['file'],
            'deployment_decision': 'REJECT',
            'overall_quality_score': 0.0,
            'error': str(e)
        }

def generate_summary(evaluations: List[Dict]) -> Dict:
    """generate summary of static evaluations"""

    total = len(evaluations)

    breakdown = {'APPROVE': 0, 'CONDITIONAL': 0, 'REJECT': 0}
    quality_scores = []

    for eval_result in evaluations:
        decision = eval_result.get('deployment_decision', 'REJECT')
        breakdown[decision] = breakdown.get(decision, 0) + 1
        quality_scores.append(eval_result.get('overall_quality_score', 0.0))

    avg_quality = sum(quality_scores) / total if total > 0 else 0.0

    return {
        'total_rules_evaluated': total,
        'deployment_breakdown': breakdown,
        'avg_quality_score': round(avg_quality, 2),
        'rules_passing_threshold': breakdown['APPROVE'] + breakdown['CONDITIONAL'],
        'assessment': f"{breakdown['APPROVE']} rules approved, {breakdown['CONDITIONAL']} conditional, {breakdown['REJECT']} rejected"
    }

def filter_passing_rules(evaluations: List[Dict], rules_dir: Path, output_dir: Path, threshold: float = 0.65):
    """filter and save only passing rules to output directory"""

    output_dir.mkdir(exist_ok=True, parents=True)

    passing_count = 0
    filtered_ids = []

    for eval_result in evaluations:
        decision = eval_result.get('deployment_decision', 'REJECT')
        quality = eval_result.get('overall_quality_score', 0.0)

        #pass threshold: APPROVE or CONDITIONAL with score >= threshold
        if decision in ['APPROVE', 'CONDITIONAL'] and quality >= threshold:
            rule_file = eval_result.get('rule_file')

            if rule_file:
                src = rules_dir / rule_file
                dst = output_dir / rule_file

                if src.exists():
                    import shutil
                    shutil.copy(src, dst)
                    passing_count += 1
                    filtered_ids.append(eval_result.get('rule_id'))

                    print(f"  ✓ Pass: {eval_result.get('rule_title', 'Unknown')[:60]}")

    return passing_count, filtered_ids

def main():
    import argparse

    parser = argparse.ArgumentParser(description='Static LLM Judge: Pre-filter rules before integration testing')
    parser.add_argument('--rules', default='generated/sigma_rules', help='Sigma rules directory')
    parser.add_argument('--tests', default='generated/tests', help='Test payloads directory')
    parser.add_argument('--output', default='generated/STATIC_QUALITY_REPORT.json', help='Output report file')
    parser.add_argument('--filter-output', help='Directory to save only passing rules (optional)')
    parser.add_argument('--threshold', type=float, default=0.65, help='Minimum quality score to pass (default: 0.65)')
    parser.add_argument('--project', help='GCP project ID')
    parser.add_argument('--location', default='us-central1', help='GCP region')
    args = parser.parse_args()

    rules_dir = Path(args.rules)
    tests_dir = Path(args.tests)
    output_file = Path(args.output)

    if not rules_dir.exists():
        print(f"ERROR: Rules directory not found: {rules_dir}")
        return 1

    #setup Vertex AI
    project_id = args.project or os.environ.get('GOOGLE_CLOUD_PROJECT')

    if not project_id:
        print("ERROR: GCP project ID not provided")
        return 1

    print(f"Using Vertex AI: {project_id} ({args.location})")
    vertexai.init(project=project_id, location=args.location)

    model = GenerativeModel('gemini-1.5-pro')

    print(f"\n{'='*80}")
    print("STATIC LLM JUDGE: PRE-FILTER EVALUATION")
    print(f"{'='*80}\n")

    #load rules
    print("[1/3] Loading Sigma rules...")
    rules = load_sigma_rules(rules_dir)
    print(f"  ✓ Loaded {len(rules)} rules")

    #load test payloads
    print("\n[2/3] Loading test payload metadata...")
    test_metadata = load_test_payloads(tests_dir)
    print(f"  ✓ Loaded test scenarios for {len(test_metadata)} rules")

    #evaluate rules
    print(f"\n[3/3] Evaluating rules (threshold: {args.threshold})...")
    evaluations = []

    for rule_id, rule_data in rules.items():
        #find test scenarios (match by ID prefix)
        rule_prefix = rule_id[:8]
        test_scenarios = test_metadata.get(rule_prefix, {})

        evaluation = evaluate_rule_static(rule_id, rule_data, test_scenarios, model)
        evaluations.append(evaluation)

    print(f"  ✓ Evaluated {len(evaluations)} rules")

    #generate summary
    summary = generate_summary(evaluations)

    #save report
    report = {
        'timestamp': datetime.now().isoformat(),
        'threshold': args.threshold,
        'summary': summary,
        'evaluations': evaluations
    }

    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"\n✓ Saved report: {output_file}")

    #filter passing rules if output specified
    if args.filter_output:
        filter_dir = Path(args.filter_output)
        print(f"\nFiltering passing rules to: {filter_dir}")

        passing_count, filtered_ids = filter_passing_rules(
            evaluations, rules_dir, filter_dir, args.threshold
        )

        print(f"\n✓ Filtered {passing_count} passing rules")

        #save filtered IDs for next stage
        with open(filter_dir / 'PASSING_RULE_IDS.json', 'w') as f:
            json.dump({'rule_ids': filtered_ids, 'count': passing_count}, f, indent=2)

    #print summary
    print(f"\n{'='*80}")
    print("EVALUATION SUMMARY")
    print(f"{'='*80}\n")
    print(f"Total Rules: {summary['total_rules_evaluated']}")
    print(f"Average Quality Score: {summary['avg_quality_score']:.2f}")
    print(f"\nDeployment Breakdown:")
    for decision, count in summary['deployment_breakdown'].items():
        pct = (count / summary['total_rules_evaluated'] * 100) if summary['total_rules_evaluated'] > 0 else 0
        print(f"  {decision:12s}: {count:2d} ({pct:5.1f}%)")
    print(f"\nPassing Threshold (≥ {args.threshold}): {summary['rules_passing_threshold']}")
    print(f"{'='*80}\n")

    #exit code based on passing rules
    if summary['rules_passing_threshold'] > 0:
        print(f"✅ {summary['rules_passing_threshold']} rules ready for integration testing")
        return 0
    else:
        print("⚠️  No rules passed quality threshold")
        return 1

if __name__ == '__main__':
    sys.exit(main())
