#!/usr/bin/env python3
"""
LLM Judge: Evaluate detection rule quality based on empirical test results

Uses Vertex AI Gemini to analyze Sigma rules + integration test results
and provide deployment recommendations.

Requires: gcloud auth application-default login
"""

import json
import yaml
import sys
import os
from pathlib import Path
from typing import Dict, List
from datetime import datetime

try:
    from google import genai
    from google.genai import types
except ImportError:
    print("ERROR: google-genai library not installed")
    print("Run: pip install google-genai")
    sys.exit(1)

def load_judge_prompt() -> str:
    """load LLM judge evaluation prompt"""
    prompt_file = Path(__file__).parent.parent / "sigma_detection_agent" / "prompts" / "llm_judge_prompt.md"

    if not prompt_file.exists():
        print(f"ERROR: Judge prompt not found: {prompt_file}")
        sys.exit(1)

    with open(prompt_file) as f:
        return f.read()

def load_sigma_rules(rules_dir: Path) -> Dict:
    """load all Sigma rules"""
    rules = {}

    rule_files = list(rules_dir.glob('*.yml')) + list(rules_dir.glob('*.yaml'))

    for rule_file in rule_files:
        with open(rule_file) as f:
            rule_yaml = yaml.safe_load(f)

        rule_id = rule_yaml.get('id')
        if rule_id:
            rules[str(rule_id)] = rule_yaml

    return rules

def load_test_results(results_file: Path) -> Dict:
    """load integration test results"""
    if not results_file.exists():
        print(f"ERROR: Test results not found: {results_file}")
        sys.exit(1)

    with open(results_file) as f:
        return json.load(f)

def load_test_payloads(tests_dir: Path, rule_id: str) -> Dict:
    """load test payload descriptions for a rule"""
    #find test directory for this rule (matches first 8 chars of UUID)
    rule_prefix = rule_id[:8]

    test_scenarios = {
        'true_positive': '',
        'false_negative': '',
        'false_positive': '',
        'true_negative': ''
    }

    for rule_dir in tests_dir.iterdir():
        if not rule_dir.is_dir():
            continue

        if rule_prefix not in rule_dir.name:
            continue

        #load payload descriptions
        for scenario_type in ['true_positive', 'false_negative', 'false_positive', 'true_negative']:
            payload_file = rule_dir / f"{scenario_type}_01.json"

            if payload_file.exists():
                with open(payload_file) as f:
                    payload = json.load(f)
                    test_scenarios[scenario_type] = payload.get('_description', '')

        break

    return test_scenarios

def evaluate_rule(rule_id: str, rule: Dict, test_results: Dict, test_payloads: Dict, client, model_name: str) -> Dict:
    """evaluate single rule using LLM judge"""

    #prepare input for judge
    evaluation_input = {
        'rule_id': rule_id,
        'rule': {
            'title': rule.get('title'),
            'description': rule.get('description'),
            'level': rule.get('level'),
            'tags': rule.get('tags', []),
            'detection': rule.get('detection'),
            'falsepositives': rule.get('falsepositives', [])
        },
        'test_results': {
            'tp': test_results.get('tp', 0),
            'fp': test_results.get('fp', 0),
            'tn': test_results.get('tn', 0),
            'fn': test_results.get('fn', 0),
            'precision': test_results.get('precision', 0.0),
            'recall': test_results.get('recall', 0.0),
            'f1_score': test_results.get('f1_score', 0.0)
        },
        'test_payloads': test_payloads
    }

    prompt = f"""Evaluate this detection rule based on empirical test results:

{json.dumps(evaluation_input, indent=2)}

Provide your evaluation in the exact JSON format specified in the rubric.
"""

    print(f"  Evaluating: {rule.get('title')[:60]}...")

    try:
        response = client.models.generate_content(
            model=model_name,
            contents=prompt
        )

        #extract JSON from response
        response_text = response.text

        #try to find JSON block
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
        return evaluation

    except json.JSONDecodeError as e:
        print(f"    ⚠ Warning: Could not parse JSON response for {rule.get('title')}")
        print(f"    Error: {e}")
        print(f"    Response: {response_text[:200]}...")

        #return minimal evaluation on parse error
        return {
            'rule_id': rule_id,
            'rule_title': rule.get('title'),
            'deployment_decision': 'REJECT',
            'overall_quality_score': 0.0,
            'error': 'Failed to parse LLM response'
        }

    except Exception as e:
        print(f"    ✗ Error evaluating rule: {e}")
        return {
            'rule_id': rule_id,
            'rule_title': rule.get('title'),
            'deployment_decision': 'REJECT',
            'overall_quality_score': 0.0,
            'error': str(e)
        }

def generate_summary_report(evaluations: List[Dict], test_results: Dict) -> Dict:
    """generate aggregate summary report"""

    total_rules = len(evaluations)

    deployment_breakdown = {
        'APPROVE': 0,
        'CONDITIONAL': 0,
        'REJECT': 0
    }

    quality_scores = []
    precisions = []
    recalls = []
    f1_scores = []

    top_performers = []
    needs_attention = []

    for eval_result in evaluations:
        decision = eval_result.get('deployment_decision', 'REJECT')
        deployment_breakdown[decision] = deployment_breakdown.get(decision, 0) + 1

        quality_score = eval_result.get('overall_quality_score', 0.0)
        quality_scores.append(quality_score)

        metrics = eval_result.get('metrics', {})
        precisions.append(metrics.get('precision', 0.0))
        recalls.append(metrics.get('recall', 0.0))
        f1_scores.append(metrics.get('f1_score', 0.0))

        #track top performers
        if metrics.get('f1_score', 0.0) >= 0.90:
            top_performers.append({
                'rule_id': eval_result.get('rule_id'),
                'title': eval_result.get('rule_title'),
                'f1_score': metrics.get('f1_score')
            })

        #track rules needing attention
        if decision == 'REJECT' or metrics.get('f1_score', 0.0) == 0.0:
            issue = 'Unknown issue'
            if metrics.get('precision', 0.0) < 0.50:
                issue = 'Low precision - too many false positives'
            elif metrics.get('recall', 0.0) == 0.0:
                issue = 'Zero recall - detection logic broken'
            elif metrics.get('f1_score', 0.0) < 0.50:
                issue = 'Poor overall performance'

            needs_attention.append({
                'rule_id': eval_result.get('rule_id'),
                'title': eval_result.get('rule_title'),
                'issue': issue
            })

    avg_precision = sum(precisions) / total_rules if total_rules > 0 else 0.0
    avg_recall = sum(recalls) / total_rules if total_rules > 0 else 0.0
    avg_f1 = sum(f1_scores) / total_rules if total_rules > 0 else 0.0
    avg_quality = sum(quality_scores) / total_rules if total_rules > 0 else 0.0

    approve_pct = (deployment_breakdown['APPROVE'] / total_rules * 100) if total_rules > 0 else 0
    conditional_pct = (deployment_breakdown['CONDITIONAL'] / total_rules * 100) if total_rules > 0 else 0
    reject_pct = (deployment_breakdown['REJECT'] / total_rules * 100) if total_rules > 0 else 0

    overall_assessment = f"""Mixed quality distribution typical of automated detection generation.
{approve_pct:.1f}% of rules are production-ready, {conditional_pct:.1f}% need minor tuning, {reject_pct:.1f}% require rework.
This is acceptable for first-pass automated generation with human review."""

    deployment_timeline = f"""Week 1: Deploy {deployment_breakdown['APPROVE']} APPROVE rules to production with monitoring.
Week 2-3: Deploy {deployment_breakdown['CONDITIONAL']} CONDITIONAL rules to staging environment for testing.
Month 2: Rework and retest {deployment_breakdown['REJECT']} REJECT rules before deployment."""

    return {
        'total_rules_evaluated': total_rules,
        'deployment_breakdown': deployment_breakdown,
        'aggregate_metrics': {
            'avg_precision': round(avg_precision, 2),
            'avg_recall': round(avg_recall, 2),
            'avg_f1_score': round(avg_f1, 2),
            'avg_quality_score': round(avg_quality, 2)
        },
        'overall_assessment': overall_assessment.strip(),
        'top_performing_rules': sorted(top_performers, key=lambda x: x['f1_score'], reverse=True)[:5],
        'rules_needing_attention': needs_attention,
        'deployment_timeline': deployment_timeline.strip()
    }

def print_summary(summary: Dict, evaluations: List[Dict]):
    """print summary report to console"""
    print(f"\n{'='*80}")
    print("LLM JUDGE EVALUATION SUMMARY")
    print(f"{'='*80}\n")

    print(f"Total Rules Evaluated: {summary['total_rules_evaluated']}")
    print(f"\nDeployment Breakdown:")
    for decision, count in summary['deployment_breakdown'].items():
        pct = (count / summary['total_rules_evaluated'] * 100) if summary['total_rules_evaluated'] > 0 else 0
        print(f"  {decision:12s}: {count:2d} ({pct:5.1f}%)")

    print(f"\nAggregate Metrics:")
    metrics = summary['aggregate_metrics']
    print(f"  Avg Precision:     {metrics['avg_precision']:.2f}")
    print(f"  Avg Recall:        {metrics['avg_recall']:.2f}")
    print(f"  Avg F1 Score:      {metrics['avg_f1_score']:.2f}")
    print(f"  Avg Quality Score: {metrics['avg_quality_score']:.2f}")

    print(f"\nOverall Assessment:")
    print(f"  {summary['overall_assessment']}")

    if summary['top_performing_rules']:
        print(f"\nTop Performing Rules:")
        for rule in summary['top_performing_rules']:
            print(f"  ✓ {rule['title'][:60]} (F1: {rule['f1_score']:.2f})")

    if summary['rules_needing_attention']:
        print(f"\nRules Needing Attention:")
        for rule in summary['rules_needing_attention']:
            print(f"  ⚠ {rule['title'][:50]}")
            print(f"    Issue: {rule['issue']}")

    print(f"\nDeployment Timeline:")
    for line in summary['deployment_timeline'].split('\n'):
        print(f"  {line}")

    print(f"\n{'='*80}\n")

    #per-rule details
    print("PER-RULE EVALUATION DETAILS")
    print(f"{'='*80}\n")

    for eval_result in evaluations:
        title = eval_result.get('rule_title', 'Unknown')
        decision = eval_result.get('deployment_decision', 'UNKNOWN')
        quality = eval_result.get('overall_quality_score', 0.0)
        metrics = eval_result.get('metrics', {})

        #decision emoji
        if decision == 'APPROVE':
            emoji = '✅'
        elif decision == 'CONDITIONAL':
            emoji = '⚠️'
        else:
            emoji = '❌'

        print(f"{emoji} {title}")
        print(f"   Decision: {decision} (Quality: {quality:.2f})")
        print(f"   Metrics: P={metrics.get('precision', 0):.2f} R={metrics.get('recall', 0):.2f} F1={metrics.get('f1_score', 0):.2f}")

        if eval_result.get('strengths'):
            print(f"   Strengths:")
            for strength in eval_result['strengths'][:2]:
                print(f"     • {strength[:70]}")

        if eval_result.get('recommendations'):
            print(f"   Recommendations:")
            for rec in eval_result['recommendations'][:2]:
                print(f"     → {rec[:70]}")

        print()

def main():
    import argparse
    import os

    parser = argparse.ArgumentParser(description='LLM Judge: Evaluate detection rules')
    parser.add_argument('--rules', default='generated/sigma_rules',
                       help='Directory containing Sigma rules')
    parser.add_argument('--tests', default='generated/tests',
                       help='Directory containing test payloads')
    parser.add_argument('--results', default='generated/INTEGRATION_TEST_RESULTS.json',
                       help='Integration test results file')
    parser.add_argument('--output', default='generated/QUALITY_REPORT.json',
                       help='Output quality report file')
    parser.add_argument('--project', help='GCP project ID (or set GOOGLE_CLOUD_PROJECT env var)')
    parser.add_argument('--location', default='us-central1', help='GCP region (default: us-central1)')
    args = parser.parse_args()

    rules_dir = Path(args.rules)
    tests_dir = Path(args.tests)
    results_file = Path(args.results)
    output_file = Path(args.output)

    #check directories exist
    if not rules_dir.exists():
        print(f"ERROR: Rules directory not found: {rules_dir}")
        return 1

    if not tests_dir.exists():
        print(f"ERROR: Tests directory not found: {tests_dir}")
        return 1

    if not results_file.exists():
        print(f"ERROR: Test results not found: {results_file}")
        return 1

    #setup Vertex AI via google-genai SDK (uses ADC - Application Default Credentials)
    project_id = args.project or os.environ.get('GOOGLE_CLOUD_PROJECT')

    if not project_id:
        print("ERROR: GCP project ID not provided")
        print("Set GOOGLE_CLOUD_PROJECT environment variable or use --project")
        print("\nTip: gcloud config get-value project")
        return 1

    #enable Vertex AI mode
    os.environ['GOOGLE_GENAI_USE_VERTEXAI'] = 'true'

    print(f"Using Vertex AI in project: {project_id} (region: {args.location})")
    print(f"Authentication: Application Default Credentials")

    client = genai.Client(
        vertexai=True,
        project=project_id,
        location=args.location
    )

    #use Gemini 2.5 Flash for cost-efficient evaluation
    model_name = 'gemini-2.5-flash'

    print(f"\n{'='*80}")
    print("LLM JUDGE: DETECTION RULE QUALITY EVALUATION")
    print(f"{'='*80}\n")
    print(f"Rules: {rules_dir}")
    print(f"Tests: {tests_dir}")
    print(f"Results: {results_file}")
    print()

    #load judge prompt
    judge_prompt = load_judge_prompt()

    #load all data
    print("[1/4] Loading Sigma rules...")
    rules = load_sigma_rules(rules_dir)
    print(f"  ✓ Loaded {len(rules)} rules")

    print("\n[2/4] Loading integration test results...")
    test_results = load_test_results(results_file)
    print(f"  ✓ Loaded results for {len(test_results)} rules")

    #evaluate each rule
    print("\n[3/4] Evaluating rules with LLM judge...")
    evaluations = []

    for rule_id, results in test_results.items():
        if rule_id not in rules:
            print(f"  ⚠ Warning: Rule {rule_id} not found in rules directory")
            continue

        rule = rules[rule_id]
        test_payloads = load_test_payloads(tests_dir, rule_id)

        evaluation = evaluate_rule(rule_id, rule, results, test_payloads, client, model_name)
        evaluations.append(evaluation)

    print(f"  ✓ Evaluated {len(evaluations)} rules")

    #generate summary
    print("\n[4/4] Generating summary report...")
    summary = generate_summary_report(evaluations, test_results)

    #save results
    output = {
        'timestamp': datetime.now().isoformat(),
        'summary': summary,
        'rule_evaluations': evaluations
    }

    output_file.parent.mkdir(exist_ok=True, parents=True)
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"  ✓ Saved quality report to: {output_file}")

    #print summary
    print_summary(summary, evaluations)

    #exit code based on overall quality
    if summary['aggregate_metrics']['avg_quality_score'] >= 0.75:
        print("✅ Overall quality PASS (≥ 0.75)")
        return 0
    elif summary['aggregate_metrics']['avg_quality_score'] >= 0.60:
        print("⚠️  Overall quality CONDITIONAL (0.60-0.74)")
        return 0
    else:
        print("❌ Overall quality FAIL (< 0.60)")
        return 1

if __name__ == '__main__':
    sys.exit(main())
