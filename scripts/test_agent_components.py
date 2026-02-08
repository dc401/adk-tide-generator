#!/usr/bin/env python3
"""Test Agent Components (No GCP Required)

Tests that all agent components can be imported and validated
without needing GCP credentials.
"""

import sys
from pathlib import Path

#add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


def test_imports():
    """test all agent imports work"""
    print("\n[1/5] Testing Agent Imports...")

    try:
        from detection_agent import schemas
        print("  ✓ schemas module")

        from detection_agent.schemas import (
            DetectionRule,
            DetectionRuleOutput,
            ValidationResult,
            EvaluationResult,
            SecurityScanResult,
        )
        print("  ✓ schema classes")

        from detection_agent.tools import load_cti_files
        print("  ✓ load_cti_files tool")

        from detection_agent import agent
        print("  ✓ agent module")

        from detection_agent import refinement
        print("  ✓ refinement module")

        from detection_agent import per_rule_refinement
        print("  ✓ per_rule_refinement module")

        return True

    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_cti_loading():
    """test CTI file loading"""
    print("\n[2/5] Testing CTI Loading...")

    try:
        from detection_agent.tools import load_cti_files

        result = load_cti_files('cti_src')

        if result['files_loaded'] > 0:
            print(f"  ✓ Loaded {result['files_loaded']} files")
            print(f"  ✓ Text content: {len(result['text_content'])} chars")
            return True
        else:
            print("  ✗ No files loaded")
            return False

    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        return False


def test_schema_validation():
    """test pydantic schema validation"""
    print("\n[3/5] Testing Schema Validation...")

    try:
        from detection_agent.schemas import DetectionRule
        import yaml

        #load an existing rule
        rule_file = Path('generated/detection_rules/akira_ransomware_-_shadow_copy_deletion_(t1490).yml')

        if not rule_file.exists():
            print("  ⚠ No test rules found, skipping schema validation")
            return True

        with open(rule_file) as f:
            rule_data = yaml.safe_load(f)

        #validate with pydantic
        rule = DetectionRule(**rule_data)

        print(f"  ✓ Rule name: {rule.name}")
        print(f"  ✓ Query length: {len(rule.query)} chars")
        print(f"  ✓ Test cases: {len(rule.test_cases)}")
        print(f"  ✓ Severity: {rule.severity}")

        return True

    except Exception as e:
        print(f"  ✗ FAIL: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_prompts_exist():
    """test all prompts are present"""
    print("\n[4/5] Testing Prompts...")

    prompts_dir = Path('detection_agent/prompts')
    required_prompts = [
        'detection_generator.md',
        'validator.md',
        'evaluator.md',
        'security_guard.md'
    ]

    missing = []
    for prompt in required_prompts:
        prompt_file = prompts_dir / prompt
        if prompt_file.exists():
            size = prompt_file.stat().st_size
            print(f"  ✓ {prompt} ({size} bytes)")
        else:
            print(f"  ✗ MISSING: {prompt}")
            missing.append(prompt)

    return len(missing) == 0


def test_scripts_exist():
    """test all scripts are present and executable"""
    print("\n[5/5] Testing Scripts...")

    scripts_dir = Path('scripts')
    required_scripts = [
        'validate_rules.py',
        'integration_test_ci.py',
        'run_llm_judge.py',
        'test_core.sh',
        'validate_local.py',
    ]

    missing = []
    for script in required_scripts:
        script_file = scripts_dir / script
        if script_file.exists():
            executable = script_file.stat().st_mode & 0o111 != 0
            status = "✓ executable" if executable else "✓ exists"
            print(f"  {status}: {script}")
        else:
            print(f"  ✗ MISSING: {script}")
            missing.append(script)

    return len(missing) == 0


def main():
    print("="*80)
    print("AGENT COMPONENTS TEST (No GCP Required)")
    print("="*80)

    tests = [
        ("Imports", test_imports),
        ("CTI Loading", test_cti_loading),
        ("Schema Validation", test_schema_validation),
        ("Prompts", test_prompts_exist),
        ("Scripts", test_scripts_exist),
    ]

    results = []
    for name, test_func in tests:
        passed = test_func()
        results.append((name, passed))

    #summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)

    passed_count = sum(1 for _, p in results if p)
    total_count = len(results)

    print(f"\nTests: {passed_count}/{total_count} passed")

    if passed_count < total_count:
        print("\nFailed Tests:")
        for name, passed in results:
            if not passed:
                print(f"  - {name}")
        return 1

    print("\n✓ All component tests passed!")
    print("\nNext Steps:")
    print("  1. Set GOOGLE_CLOUD_PROJECT env variable")
    print("  2. Run: python run_agent.py --interactive")
    print("  3. Or run: python scripts/validate_rules.py --project YOUR_PROJECT")

    return 0


if __name__ == '__main__':
    sys.exit(main())
