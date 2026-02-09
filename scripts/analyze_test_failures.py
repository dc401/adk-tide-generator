#!/usr/bin/env python3
"""analyze test failures to generate feedback for rule refinement"""

import json
import sys
from pathlib import Path
from typing import Dict, List

def analyze_failures(test_results_path: Path) -> str:
    """generate detailed failure analysis for LLM feedback"""

    with open(test_results_path) as f:
        results = json.load(f)

    overall = results['overall_metrics']
    precision = overall['precision']
    recall = overall['recall']

    feedback_sections = []

    #overall assessment
    feedback_sections.append("# DETECTION QUALITY ANALYSIS\n")
    feedback_sections.append(f"**Overall Precision:** {precision * 100:.1f}% (Target: ≥60%)")
    feedback_sections.append(f"**Overall Recall:** {recall * 100:.1f}% (Target: ≥70%)\n")

    if precision < 0.60:
        feedback_sections.append("⚠️  **TOO MANY FALSE POSITIVES** - Queries are too broad\n")
    if recall < 0.70:
        feedback_sections.append("⚠️  **MISSING ATTACKS** - Queries are too narrow\n")

    #per-rule analysis
    feedback_sections.append("---\n")
    feedback_sections.append("# RULE-BY-RULE ANALYSIS\n")

    for rule_result in results['rule_results']:
        rule_name = rule_result['rule_name']
        query = rule_result['query']
        metrics = rule_result['metrics']
        details = rule_result['details']

        feedback_sections.append(f"\n## Rule: {rule_name}\n")
        feedback_sections.append(f"**Query:** `{query}`\n")
        feedback_sections.append(f"**Precision:** {metrics['precision'] * 100:.1f}% | **Recall:** {metrics['recall'] * 100:.1f}%")
        feedback_sections.append(f"**Results:** {metrics['TP']} TP, {metrics['FN']} FN, {metrics['FP']} FP, {metrics['TN']} TN\n")

        #false positives analysis
        fps = [d for d in details if d['outcome'] == 'FP']
        if fps:
            feedback_sections.append(f"\n### ❌ FALSE POSITIVES ({len(fps)}) - Query too broad:\n")
            for fp in fps:
                feedback_sections.append(f"- **Test {fp['test_num']}:** {fp['description']}")
                feedback_sections.append(f"  - Expected: No match (benign activity)")
                feedback_sections.append(f"  - Actual: Matched (incorrect alert)")
                feedback_sections.append(f"  - **Fix needed:** Add exclusion filter or tighten query conditions\n")

        #false negatives analysis
        fns = [d for d in details if d['outcome'] == 'FN']
        if fns:
            feedback_sections.append(f"\n### ❌ FALSE NEGATIVES ({len(fns)}) - Query too narrow:\n")
            for fn in fns:
                feedback_sections.append(f"- **Test {fn['test_num']}:** {fn['description']}")
                feedback_sections.append(f"  - Expected: Match (malicious activity)")
                feedback_sections.append(f"  - Actual: No match (missed attack)")
                feedback_sections.append(f"  - **Fix needed:** Broaden query to include this attack variant\n")

        #suggested fixes
        feedback_sections.append("\n### 🔧 RECOMMENDED FIXES:\n")

        if fps and not fns:
            feedback_sections.append("- **Primary issue:** Too many false positives")
            feedback_sections.append("- **Action:** Add filter conditions to exclude benign activity")
            feedback_sections.append("- **Example:** Add parent process checks, user context filters, or time-based exclusions\n")

        elif fns and not fps:
            feedback_sections.append("- **Primary issue:** Missing attack detections")
            feedback_sections.append("- **Action:** Broaden query to cover attack variants")
            feedback_sections.append("- **Example:** Use wildcards, add alternate command patterns, include process ancestry\n")

        elif fps and fns:
            feedback_sections.append("- **Primary issue:** Query needs rebalancing")
            feedback_sections.append("- **Action 1:** Fix false positives first (add filters)")
            feedback_sections.append("- **Action 2:** Then broaden for missed attacks (alternate patterns)")
            feedback_sections.append("- **Goal:** Balance precision and recall\n")

        else:
            feedback_sections.append("- ✓ This rule is performing well - no changes needed\n")

    #summary recommendations
    feedback_sections.append("\n---\n")
    feedback_sections.append("# REGENERATION INSTRUCTIONS\n")
    feedback_sections.append("Regenerate the SAME detection rules with improvements based on analysis above.\n")
    feedback_sections.append("For each rule:\n")
    feedback_sections.append("1. Review the FP/FN cases listed")
    feedback_sections.append("2. Apply the recommended fixes")
    feedback_sections.append("3. Explain what you changed and why")
    feedback_sections.append("4. Keep the same rule names and TTPs")
    feedback_sections.append("5. Preserve test cases that passed\n")

    return "\n".join(feedback_sections)

def main():
    if len(sys.argv) < 2:
        print("Usage: python analyze_test_failures.py <test_results.json>")
        sys.exit(1)

    test_results = Path(sys.argv[1])

    if not test_results.exists():
        print(f"Error: {test_results} not found")
        sys.exit(1)

    feedback = analyze_failures(test_results)
    print(feedback)

if __name__ == '__main__':
    main()
