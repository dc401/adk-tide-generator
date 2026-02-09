#!/usr/bin/env python3
"""Demo: TTP validator logic without API calls

Shows what the TTP validator would check for our production rules
"""

import yaml
from pathlib import Path

def analyze_test_case(rule: dict, test_case: dict):
    """Simulate TTP validator checks"""

    print("="*80)
    print(f"TTP VALIDATION ANALYSIS: {test_case['type']} Test Case")
    print("="*80)
    print()

    # Extract key info
    rule_name = rule['name']
    query = rule['query']
    test_type = test_case['type']
    description = test_case['description']
    log_entry = test_case['log_entry']
    expected_match = test_case['expected_match']
    evasion = test_case.get('evasion_technique')

    print(f"Rule: {rule_name}")
    print(f"Test Type: {test_type}")
    print(f"Description: {description}")
    print()

    # Extract command details
    process = log_entry.get('process', {})
    command_line = process.get('command_line', '')
    process_name = process.get('name', '')

    print("LOG ENTRY:")
    print(f"  Process: {process_name}")
    print(f"  Command: {command_line}")
    print(f"  Expected to match query: {expected_match}")
    print()

    # Check 1: Command Syntax Realism
    print("[CHECK 1] COMMAND SYNTAX REALISM")
    print("-" * 40)

    if 'vssadmin' in command_line.lower():
        flags = ['/all', '/quiet', 'delete', 'shadows']
        found_flags = [f for f in flags if f in command_line.lower()]

        print(f"  Tool: vssadmin.exe")
        print(f"  Flags found: {found_flags}")

        if '/all' in command_line and '/quiet' in command_line:
            print(f"  ✓ REALISTIC - Uses common ransomware flags")
            print(f"    - /all: Deletes ALL shadow copies")
            print(f"    - /quiet: Suppresses confirmation prompts")
            print(f"  Research: Seen in Akira, Conti, LockBit ransomware")
        elif 'delete' in command_line and 'shadows' in command_line:
            print(f"  ⚠️  PARTIAL - Valid syntax but missing common flags")
            print(f"    - Missing /all or /quiet flags")
            print(f"    - Real attacks typically use /all /quiet")
        else:
            print(f"  ⚠️  Review needed")

    elif 'wmic' in command_line.lower():
        if 'shadowcopy' in command_line.lower() and 'delete' in command_line.lower():
            print(f"  Tool: wmic.exe")
            print(f"  ✓ REALISTIC - WMIC shadow copy deletion")
            print(f"  Research: Alternative method seen in malware")
        else:
            print(f"  ⚠️  Review needed")

    elif 'bcdedit' in command_line.lower():
        if 'recoveryenabled' in command_line.lower() and 'no' in command_line.lower():
            print(f"  Tool: bcdedit.exe")
            print(f"  ✓ REALISTIC - Disables Windows recovery")
            print(f"  Research: Common in ransomware T1490")
        else:
            print(f"  ⚠️  Review needed")

    elif 'powershell' in process_name.lower():
        if 'WmiObject' in command_line and 'ShadowCopy' in command_line and 'Delete()' in command_line:
            print(f"  Tool: PowerShell + WMI API")
            print(f"  ✓ REALISTIC - Advanced evasion technique")
            print(f"  Research: Seen in sophisticated ransomware (Conti, BlackCat)")
        else:
            print(f"  ⚠️  Review needed")

    else:
        print(f"  ℹ️  No specific validation (baseline activity)")

    print()

    # Check 2: TTP Alignment
    print("[CHECK 2] TTP ALIGNMENT (T1490 - Inhibit System Recovery)")
    print("-" * 40)

    if test_type == 'TP':
        if 'vssadmin' in command_line.lower() or 'wmic' in command_line.lower() or 'bcdedit' in command_line.lower():
            print(f"  ✓ ALIGNED - Command achieves T1490 objective")
            print(f"    - Deletes/disables shadow copies or recovery")
            print(f"    - Prevents system restoration after ransomware")
        else:
            print(f"  ✗ MISALIGNED - Command doesn't inhibit recovery")

    elif test_type == 'FN':
        print(f"  ✓ FN case - Documents evasion technique")
        print(f"  Evasion: {evasion}")

    else:
        print(f"  ℹ️  {test_type} case - Not an attack")

    print()

    # Check 3: Evasion Validity (FN only)
    if test_type == 'FN':
        print("[CHECK 3] EVASION TECHNIQUE VALIDITY")
        print("-" * 40)

        # Simulate query matching
        query_checks = {
            'process.name': ['vssadmin', 'wmic', 'bcdedit'],
            'command_line': ['delete', 'shadows']
        }

        process_name_match = any(tool in process_name.lower() for tool in query_checks['process.name'])
        command_line_match = all(keyword in command_line.lower() for keyword in query_checks['command_line'])

        print(f"  Query checks process.name:(*vssadmin* OR *wmic* OR *bcdedit*)")
        print(f"    Process name '{process_name}' matches: {process_name_match}")
        print()
        print(f"  Query checks command_line:(*delete*shadows*)")
        print(f"    Command '{command_line[:50]}...' matches: {command_line_match}")
        print()

        if not process_name_match or not command_line_match:
            print(f"  ✓ VALID EVASION - Would bypass detection")
            print(f"    Reason: Process name or command pattern not in query")
        else:
            print(f"  ✗ INVALID EVASION - Would still be detected!")
            print(f"    Reason: Matches both process name AND command pattern")

        print()

    # Check 4: Field Realism
    print("[CHECK 4] FIELD VALUE REALISM")
    print("-" * 40)

    event = log_entry.get('event', {})
    if event.get('category') == 'process' and event.get('type') == 'start':
        print(f"  ✓ Core ECS fields present (event.category, event.type)")
    else:
        print(f"  ⚠️  Missing core ECS fields")

    if '@timestamp' in log_entry:
        print(f"  ✓ Timestamp present: {log_entry['@timestamp']}")

    if process.get('executable'):
        exe_path = process['executable']
        if 'C:\\Windows\\System32' in exe_path or 'C:\\Windows\\' in exe_path:
            print(f"  ✓ Realistic Windows path: {exe_path}")
        else:
            print(f"  ⚠️  Unusual path: {exe_path}")

    user = log_entry.get('user', {})
    if user.get('name'):
        print(f"  ✓ User context: {user['name']}")

    print()

    # Final Verdict
    print("="*80)
    print("VALIDATION VERDICT")
    print("="*80)

    if test_type == 'TP':
        print(f"✓ TRUE POSITIVE test case appears VALID")
        print(f"  - Realistic command syntax")
        print(f"  - Achieves T1490 objective")
        print(f"  - Field values realistic")
        print()
        print(f"Confidence: HIGH (would verify with MITRE/threat intel research)")

    elif test_type == 'FN':
        if not process_name_match or not command_line_match:
            print(f"✓ FALSE NEGATIVE test case appears VALID")
            print(f"  - Evasion technique would bypass detection")
            print(f"  - Documented in real ransomware")
            print()
            print(f"Confidence: HIGH (would verify with threat reports)")
        else:
            print(f"✗ FALSE NEGATIVE test case appears INVALID")
            print(f"  - Evasion claim is false - would still be detected")
            print()
            print(f"Recommendation: Mark as TP, not FN")

    elif test_type == 'FP':
        print(f"✓ FALSE POSITIVE test case for tuning")
        print(f"  - Represents legitimate admin activity")
        print(f"  - Helps identify detection blind spots")

    else:
        print(f"✓ TRUE NEGATIVE baseline test case")

    print()

def main():
    # Load shadow copy deletion rule
    rule_file = Path('production_rules/windows_-_akira_ransomware_shadow_copy_deletion.yml')

    with open(rule_file) as f:
        rule = yaml.safe_load(f)

    print("\n" + "="*80)
    print("TTP INTENT VALIDATOR - DEMONSTRATION")
    print("="*80)
    print()
    print("This demonstrates what the TTP validator checks WITHOUT calling APIs.")
    print("In production, it would research MITRE ATT&CK, threat reports, and tool docs.")
    print()

    # Analyze each test case
    test_cases = rule.get('test_cases', [])

    for i, test_case in enumerate(test_cases[:3], 1):  # First 3 for demo
        print(f"\n\nTEST CASE {i}/{len(test_cases)}")
        analyze_test_case(rule, test_case)

        if i < 3:
            input("\nPress Enter to continue to next test case...")

if __name__ == '__main__':
    main()
