#!/usr/bin/env python3
"""quality-driven retry loop for detection rule generation"""

import json
import subprocess
from pathlib import Path
from typing import Dict, Optional

from detection_agent.agent import run_detection_agent

async def run_with_quality_retry(
    cti_dir: Path,
    output_dir: Path,
    project_id: str,
    location: str,
    max_iterations: int = 3,
    precision_threshold: float = 0.60,
    recall_threshold: float = 0.70
) -> Dict:
    """run detection agent with quality-driven retry loop

    iteration workflow:
    1. generate rules from CTI
    2. run integration tests
    3. check quality metrics
    4. if fail: analyze failures → regenerate with feedback
    5. repeat until pass or max iterations
    """

    print(f"\n{'='*80}")
    print("QUALITY-DRIVEN DETECTION GENERATION")
    print(f"{'='*80}")
    print(f"Quality Thresholds: Precision ≥ {precision_threshold*100:.0f}%, Recall ≥ {recall_threshold*100:.0f}%")
    print(f"Max Iterations: {max_iterations}")
    print(f"{'='*80}\n")

    iteration_history = []
    feedback_content = None

    for iteration in range(1, max_iterations + 1):
        print(f"\n{'='*80}")
        print(f"ITERATION {iteration}/{max_iterations}")
        print(f"{'='*80}\n")

        if iteration_history:
            print("Previous iterations:")
            for prev in iteration_history:
                print(f"  Iteration {prev['iteration']}:")
                print(f"    Precision: {prev['precision']*100:.1f}% | Recall: {prev['recall']*100:.1f}%")
                print(f"    Status: {prev['status']}")
            print()

        #run detection agent (with feedback if not first iteration)
        try:
            if feedback_content:
                print(f"Generating rules WITH feedback from iteration {iteration - 1}...\n")
                #save feedback for agent to use
                feedback_file = output_dir / f"quality_feedback_iter{iteration}.txt"
                with open(feedback_file, 'w') as f:
                    f.write(feedback_content)
            else:
                print("Generating rules from CTI (first attempt)...\n")

            result = await run_detection_agent(
                cti_dir,
                output_dir,
                project_id,
                location
            )

            rules_generated = result.get('rules_generated', 0)

            if rules_generated == 0:
                print(f"\n⚠️  No rules generated on iteration {iteration}")
                iteration_history.append({
                    'iteration': iteration,
                    'rules_generated': 0,
                    'precision': 0.0,
                    'recall': 0.0,
                    'status': 'FAILED - No rules'
                })
                continue

            print(f"\n✓ Generated {rules_generated} rules")

            #run integration tests
            print(f"\nRunning integration tests...")
            test_result = run_integration_tests(output_dir)

            if not test_result:
                print(f"\n⚠️  Integration tests failed on iteration {iteration}")
                iteration_history.append({
                    'iteration': iteration,
                    'rules_generated': rules_generated,
                    'precision': 0.0,
                    'recall': 0.0,
                    'status': 'FAILED - Test execution error'
                })
                continue

            precision = test_result['precision']
            recall = test_result['recall']

            print(f"\n{'='*80}")
            print(f"ITERATION {iteration} RESULTS")
            print(f"{'='*80}")
            print(f"Precision: {precision*100:.1f}% (threshold: {precision_threshold*100:.0f}%)")
            print(f"Recall: {recall*100:.1f}% (threshold: {recall_threshold*100:.0f}%)")
            print(f"F1 Score: {test_result['f1_score']:.3f}")
            print(f"{'='*80}\n")

            #check quality thresholds
            precision_pass = precision >= precision_threshold
            recall_pass = recall >= recall_threshold

            if precision_pass and recall_pass:
                print(f"\n{'='*80}")
                print(f"✓ SUCCESS ON ITERATION {iteration}")
                print(f"{'='*80}")
                print(f"Quality thresholds met!")
                print(f"  Precision: {precision*100:.1f}% ✓")
                print(f"  Recall: {recall*100:.1f}% ✓")
                print(f"Iterations used: {iteration}/{max_iterations}")
                print(f"{'='*80}\n")

                return {
                    'rules_generated': rules_generated,
                    'precision': precision,
                    'recall': recall,
                    'f1_score': test_result['f1_score'],
                    'iterations_used': iteration,
                    'quality_passed': True,
                    'iteration_history': iteration_history + [{
                        'iteration': iteration,
                        'rules_generated': rules_generated,
                        'precision': precision,
                        'recall': recall,
                        'status': 'PASSED'
                    }]
                }

            #quality check failed - prepare for next iteration
            print(f"\n⚠️  Quality thresholds NOT met:")
            if not precision_pass:
                print(f"  ❌ Precision: {precision*100:.1f}% < {precision_threshold*100:.0f}%")
            if not recall_pass:
                print(f"  ❌ Recall: {recall*100:.1f}% < {recall_threshold*100:.0f}%")

            iteration_history.append({
                'iteration': iteration,
                'rules_generated': rules_generated,
                'precision': precision,
                'recall': recall,
                'status': 'FAILED - Below quality threshold'
            })

            #analyze failures for feedback (if not last iteration)
            if iteration < max_iterations:
                print(f"\nAnalyzing test failures for iteration {iteration + 1}...")
                feedback_content = analyze_test_failures(output_dir / 'test_results.json')

                if feedback_content:
                    print(f"✓ Generated feedback for next iteration")
                    print(f"  Preparing to regenerate with quality improvements...\n")
                else:
                    print(f"⚠️  Could not generate feedback - will retry without it\n")

        except Exception as e:
            print(f"\n✗ Error on iteration {iteration}: {e}")
            iteration_history.append({
                'iteration': iteration,
                'rules_generated': 0,
                'precision': 0.0,
                'recall': 0.0,
                'status': f'ERROR: {str(e)[:100]}'
            })

    #max iterations reached without passing
    print(f"\n{'='*80}")
    print(f"⚠️  MAX ITERATIONS REACHED ({max_iterations})")
    print(f"{'='*80}")
    print("Quality thresholds not met after all attempts")
    print("\nBest result:")
    if iteration_history:
        best = max(iteration_history, key=lambda x: x.get('precision', 0) + x.get('recall', 0))
        print(f"  Iteration {best['iteration']}")
        print(f"  Precision: {best['precision']*100:.1f}%")
        print(f"  Recall: {best['recall']*100:.1f}%")
    print(f"{'='*80}\n")

    return {
        'rules_generated': iteration_history[-1].get('rules_generated', 0) if iteration_history else 0,
        'precision': iteration_history[-1].get('precision', 0) if iteration_history else 0,
        'recall': iteration_history[-1].get('recall', 0) if iteration_history else 0,
        'f1_score': 0.0,
        'iterations_used': max_iterations,
        'quality_passed': False,
        'iteration_history': iteration_history
    }

def run_integration_tests(output_dir: Path) -> Optional[Dict]:
    """run integration tests and return quality metrics"""

    rules_dir = output_dir / 'detection_rules'
    if not rules_dir.exists():
        print(f"  ✗ No detection_rules directory found")
        return None

    #note: this assumes elasticsearch is already running (GitHub Actions setup)
    #for local testing, would need to start docker container first

    try:
        cmd = [
            'python3',
            'scripts/execute_detection_tests.py',
            '--rules-dir', str(rules_dir),
            '--es-url', 'http://localhost:9200'
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if result.returncode != 0:
            print(f"  ✗ Test execution failed: {result.stderr}")
            return None

        #load test results
        test_results_file = Path('test_results.json')
        if not test_results_file.exists():
            print(f"  ✗ No test results file generated")
            return None

        with open(test_results_file) as f:
            test_results = json.load(f)

        metrics = test_results.get('overall_metrics', {})

        return {
            'precision': metrics.get('precision', 0.0),
            'recall': metrics.get('recall', 0.0),
            'f1_score': metrics.get('f1_score', 0.0),
            'tp': metrics.get('TP', 0),
            'fn': metrics.get('FN', 0),
            'fp': metrics.get('FP', 0),
            'tn': metrics.get('TN', 0)
        }

    except Exception as e:
        print(f"  ✗ Error running tests: {e}")
        return None

def analyze_test_failures(test_results_path: Path) -> Optional[str]:
    """analyze test failures and generate feedback"""

    if not test_results_path.exists():
        return None

    try:
        cmd = ['python3', 'scripts/analyze_test_failures.py', str(test_results_path)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            return result.stdout
        else:
            print(f"  ⚠️  Failure analysis error: {result.stderr}")
            return None

    except Exception as e:
        print(f"  ⚠️  Could not analyze failures: {e}")
        return None
