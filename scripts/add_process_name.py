#!/usr/bin/env python3
"""Quick fix: Add process.name field extracted from process.executable"""

import json
import os
from pathlib import Path

tests_dir = Path('generated/tests')

for rule_dir in tests_dir.iterdir():
    if not rule_dir.is_dir():
        continue

    for payload_file in rule_dir.glob('*.json'):
        with open(payload_file) as f:
            payload = json.load(f)

        if 'log_entry' in payload and 'process' in payload['log_entry']:
            process = payload['log_entry']['process']

            #add/fix process.name from process.executable
            if 'executable' in process:
                exe_path = process['executable']
                correct_name = exe_path.split('\\')[-1] if '\\' in exe_path else os.path.basename(exe_path)

                #always set or fix if wrong
                if 'name' not in process or '\\' in process.get('name', ''):
                    process['name'] = correct_name
                    print(f"Fixed process.name in {payload_file.name}: {correct_name}")

            #add/fix process.parent.name from process.parent.executable
            if 'parent' in process and 'executable' in process['parent']:
                parent_exe = process['parent']['executable']
                correct_parent_name = parent_exe.split('\\')[-1] if '\\' in parent_exe else os.path.basename(parent_exe)

                if 'name' not in process['parent'] or '\\' in process['parent'].get('name', ''):
                    process['parent']['name'] = correct_parent_name
                    print(f"Fixed process.parent.name in {payload_file.name}: {correct_parent_name}")

        #save
        with open(payload_file, 'w') as f:
            json.dump(payload, f, indent=2)

print("\n✓ Added process.name fields to all test payloads")
