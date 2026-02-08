#!/usr/bin/env python3
"""LLM Judge - Empirical Evaluation with YAML I/O"""

import asyncio
import os
import sys
import yaml
from pathlib import Path
from typing import Dict

from google import genai
from google.genai import types


def safe_yaml_parse(text: str) -> Dict:
    """safely parse YAML from LLM output"""
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError:
        #extract from markdown code block
        if '```yaml' in text:
            start = text.find('```yaml') + 7
            end = text.find('```', start)
            yaml_text = text[start:end].strip()
            return yaml.safe_load(yaml_text)
        elif '```' in text:
            start = text.find('```') + 3
            end = text.find('```', start)
            yaml_text = text[start:end].strip()
            return yaml.safe_load(yaml_text)
        raise


async def evaluate_rule_with_actual_results(
    client,
    rule_data: Dict,
    test_metrics: Dict,
    model_name: str = 'gemini-2.5-pro'
) -> Dict:
    """evaluate single rule based on actual test results"""
    
    rule_name = rule_data['name']
    metrics = test_metrics.get(rule_name, {})
    
    prompt = f"""You are a detection engineering expert evaluating Elasticsearch detection rules based on ACTUAL test results from a live SIEM.

## Detection Rule
```yaml
{yaml.dump(rule_data, default_flow_style=False, sort_keys=False)}
```

## Actual Integration Test Results

True Positives (TP):
  Detected: {metrics.get('tp_detected', 0)} / {metrics.get('tp_total', 0)} malicious events
  Status: These SHOULD alert and DID alert ✓

False Negatives (FN):
  Missed: {metrics.get('tp_total', 0) - metrics.get('tp_detected', 0)} malicious events
  FN test cases (evasion attempts): {metrics.get('fn_total', 0)}
  FN that wrongly alerted: {metrics.get('fn_missed', 0)} (evasion failed)

False Positives (FP):
  Triggered: {metrics.get('fp_triggered', 0)} / {metrics.get('fp_total', 0)} benign events
  Status: These should NOT alert but DID alert ✗

True Negatives (TN):
  Wrongly triggered: {metrics.get('tn_triggered', 0)} / {metrics.get('tn_total', 0)} normal events
  Status: These should NOT alert and should REMAIN silent

Empirical Metrics:
  Precision: {metrics.get('precision', 0):.3f} (threshold ≥0.80)
  Recall: {metrics.get('recall', 0):.3f} (threshold ≥0.70)
  F1 Score: {metrics.get('f1_score', 0):.3f}

## Your Task

Evaluate this detection rule based on its ACTUAL performance in Elasticsearch.

Return YAML:
```yaml
quality_score: 0.0-1.0  # overall quality (≥0.70 to pass)
precision_assessment:
  score: {metrics.get('precision', 0):.3f}
  pass: true/false  # ≥0.80
  issues:
    - list of false positive causes
recall_assessment:
  score: {metrics.get('recall', 0):.3f}
  pass: true/false  # ≥0.70
  issues:
    - list of missed detection causes
evasion_resistance:
  fn_tests_total: {metrics.get('fn_total', 0)}
  fn_wrongly_alerted: {metrics.get('fn_missed', 0)}
  analysis: did evasion techniques work or fail?
deployment_decision: APPROVE | REFINE | REJECT
reasoning: detailed explanation based on actual test results
recommendations:
  - specific fixes if not approved
```

Focus on:
1. Did the rule catch the attacks it was designed for? (TP rate)
2. Did it create too many false alarms? (FP rate)
3. Can attackers easily evade it? (FN test analysis)
4. Is it production-ready based on thresholds?
"""

    config = types.GenerateContentConfig(temperature=0.2)
    
    response = client.models.generate_content(
        model=model_name,
        contents=prompt,
        config=config
    )
    
    return safe_yaml_parse(response.text)


async def evaluate_rule_with_refinement(
    client,
    rule_file: Path,
    rule_data: Dict,
    test_metrics: Dict,
    max_refinement_attempts: int = 2,
    model_name: str = 'gemini-2.5-pro'
) -> Dict:
    """evaluate rule with automatic refinement if judge recommends it"""

    original_file = rule_file
    current_rule_path = rule_file
    current_rule = rule_data

    for refinement_iteration in range(max_refinement_attempts + 1):
        if refinement_iteration > 0:
            print(f"\n  🔄 Judge refinement iteration {refinement_iteration}/{max_refinement_attempts}")

        #evaluate current rule
        evaluation = await evaluate_rule_with_actual_results(
            client,
            current_rule,
            test_metrics,
            model_name
        )

        print(f"  Quality Score: {evaluation['quality_score']:.2f}")
        print(f"  Precision: {evaluation['precision_assessment']['score']:.3f} ({'✓ PASS' if evaluation['precision_assessment']['pass'] else '✗ FAIL'})")
        print(f"  Recall: {evaluation['recall_assessment']['score']:.3f} ({'✓ PASS' if evaluation['recall_assessment']['pass'] else '✗ FAIL'})")
        print(f"  Decision: {evaluation['deployment_decision']}")

        #if approved or rejected, return
        if evaluation['deployment_decision'] in ['APPROVE', 'REJECT']:
            if refinement_iteration > 0 and evaluation['deployment_decision'] == 'APPROVE':
                print(f"  ✓ Approved after {refinement_iteration} refinement(s)")
                #save refined rule back
                with open(current_rule_path) as f:
                    refined_content = f.read()
                with open(original_file, 'w') as f:
                    f.write(refined_content)

            evaluation['refined'] = refinement_iteration > 0
            evaluation['refinement_iterations'] = refinement_iteration
            return evaluation

        #if this was last attempt, return REFINE result
        if refinement_iteration >= max_refinement_attempts:
            print(f"  ⚠ Still needs refinement after {max_refinement_attempts} attempts")
            evaluation['refined'] = False
            evaluation['refinement_iterations'] = refinement_iteration
            return evaluation

        #refine based on judge's recommendations
        print(f"  Refining based on judge feedback...")

        #import refinement function
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from detection_agent.per_rule_refinement import refine_rule_with_feedback

        feedback = {
            'quality_score': evaluation['quality_score'],
            'recommendation': evaluation['deployment_decision'],
            'issues': evaluation['precision_assessment'].get('issues', []) + evaluation['recall_assessment'].get('issues', []),
            'recommendations': evaluation.get('recommendations', []),
            'precision': evaluation['precision_assessment']['score'],
            'recall': evaluation['recall_assessment']['score']
        }

        refined_rule = await refine_rule_with_feedback(
            client=client,
            original_rule=current_rule,
            feedback=feedback,
            refinement_type='judge',
            cti_content="",  #not needed for judge-based refinement
            prompts={},
            max_attempts=2
        )

        if not refined_rule:
            print(f"  ✗ Refinement failed")
            evaluation['refined'] = False
            evaluation['refinement_iterations'] = refinement_iteration
            return evaluation

        #save refined rule to temp location
        temp_refined = original_file.parent / f"{original_file.stem}_refined_judge_{refinement_iteration}.yml"
        with open(temp_refined, 'w') as f:
            yaml.dump(refined_rule, f, default_flow_style=False, sort_keys=False)

        current_rule_path = temp_refined
        current_rule = refined_rule
        print(f"  Re-evaluating refined rule...")

    #should not reach here
    evaluation['refined'] = False
    evaluation['refinement_iterations'] = max_refinement_attempts
    return evaluation


async def run_llm_judge(
    rules_dir: Path,
    test_results_file: Path,
    output_file: Path,
    project_id: str,
    location: str = 'global',
    enable_refinement: bool = True
):
    """run LLM judge on all rules with optional refinement"""

    print(f"\n{'='*80}")
    print("LLM JUDGE - EMPIRICAL EVALUATION")
    if enable_refinement:
        print("(with judge-recommended refinement)")
    print(f"{'='*80}\n")
    
    os.environ['GOOGLE_GENAI_USE_VERTEXAI'] = 'true'
    client = genai.Client(
        vertexai=True,
        project=project_id,
        location=location
    )
    
    #load integration test results (YAML)
    with open(test_results_file) as f:
        test_results = yaml.safe_load(f)
    
    metrics = test_results['metrics']
    
    print(f"Loaded: {test_results_file}")
    print(f"  Total rules tested: {len(metrics)}")
    print(f"  Passed thresholds: {test_results['summary']['rules_passed']}")
    print(f"  Failed thresholds: {test_results['summary']['rules_failed']}")
    
    evaluations = {}

    for rule_file in rules_dir.glob("*.yml"):
        with open(rule_file) as f:
            rule_data = yaml.safe_load(f)

        rule_name = rule_data['name']

        if rule_name not in metrics:
            print(f"\n⚠ Skipping {rule_name} - no test results")
            continue

        print(f"\n[Judge] Evaluating: {rule_name}")

        if enable_refinement:
            evaluation = await evaluate_rule_with_refinement(
                client,
                rule_file,
                rule_data,
                metrics,
                max_refinement_attempts=2
            )
        else:
            evaluation = await evaluate_rule_with_actual_results(
                client,
                rule_data,
                metrics
            )
            print(f"  Quality Score: {evaluation['quality_score']:.2f}")
            print(f"  Precision: {evaluation['precision_assessment']['score']:.3f} ({'✓ PASS' if evaluation['precision_assessment']['pass'] else '✗ FAIL'})")
            print(f"  Recall: {evaluation['recall_assessment']['score']:.3f} ({'✓ PASS' if evaluation['recall_assessment']['pass'] else '✗ FAIL'})")
            print(f"  Decision: {evaluation['deployment_decision']}")

        evaluations[rule_name] = evaluation
    
    approved = [r for r, e in evaluations.items() if e['deployment_decision'] == 'APPROVE']
    refine = [r for r, e in evaluations.items() if e['deployment_decision'] == 'REFINE']
    rejected = [r for r, e in evaluations.items() if e['deployment_decision'] == 'REJECT']
    
    #count judge-refined rules
    judge_refined = [r for r, e in evaluations.items() if e.get('refined', False)]

    report = {
        'timestamp': test_results['timestamp'],
        'refinement_enabled': enable_refinement,
        'summary': {
            'total_rules': len(evaluations),
            'approved': len(approved),
            'needs_refinement': len(refine),
            'rejected': len(rejected),
            'judge_refined': len(judge_refined)
        },
        'approved_rules': approved,
        'needs_refinement': refine,
        'rejected_rules': rejected,
        'judge_refined_rules': judge_refined,
        'evaluations': evaluations,
        'integration_test_summary': test_results['summary']
    }
    
    #save as YAML
    with open(output_file, 'w') as f:
        yaml.dump(report, f, default_flow_style=False, sort_keys=False)
    
    print(f"\n{'='*80}")
    print("LLM JUDGE RESULTS")
    print(f"{'='*80}")
    print(f"Total: {len(evaluations)}")
    print(f"✓ Approved: {len(approved)}")
    print(f"⚠ Needs refinement: {len(refine)}")
    print(f"✗ Rejected: {len(rejected)}")
    if enable_refinement:
        print(f"🔄 Judge refined: {len(judge_refined)}")
    print(f"\nReport saved: {output_file}")

    if len(approved) == 0 and len(evaluations) > 0:
        print("\n✗ No rules approved for deployment")
        sys.exit(1)

    return report


def main():
    import argparse

    parser = argparse.ArgumentParser(description='LLM Judge - Empirical Evaluation with Refinement')
    parser.add_argument('--rules-dir', default='generated/detection_rules')
    parser.add_argument('--test-results', default='integration_test_results.yml')
    parser.add_argument('--output', default='llm_judge_report.yml')
    parser.add_argument('--project', help='GCP project ID')
    parser.add_argument('--location', default='global')
    parser.add_argument('--no-refinement', action='store_true', help='Disable judge-recommended refinement')

    args = parser.parse_args()
    
    project_id = args.project or os.environ.get('GOOGLE_CLOUD_PROJECT')
    if not project_id:
        print("ERROR: GCP project ID required")
        sys.exit(1)
    
    rules_dir = Path(args.rules_dir)
    test_results_file = Path(args.test_results)
    
    if not rules_dir.exists():
        print(f"ERROR: {rules_dir} not found")
        sys.exit(1)
    
    if not test_results_file.exists():
        print(f"ERROR: {test_results_file} not found")
        sys.exit(1)
    
    asyncio.run(run_llm_judge(
        rules_dir=rules_dir,
        test_results_file=test_results_file,
        output_file=Path(args.output),
        project_id=project_id,
        location=args.location,
        enable_refinement=not args.no_refinement
    ))


if __name__ == '__main__':
    main()
