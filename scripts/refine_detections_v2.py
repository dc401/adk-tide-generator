#!/usr/bin/env python3
"""
Intelligent Detection Refinement Agent (v2)

Uses LLM + Google Search to dynamically research and fix detection failures.
No hard-coded field mappings - learns from documentation.

Architecture:
1. Diagnose failure type from integration test results
2. Use Google Search to research:
   - ECS field schema
   - Source log format (Sysmon, WinSec, CloudTrail, etc.)
   - Existing mapping examples
3. Dynamically generate field mapping
4. Apply conversion and validate
"""

import json
import sys
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

#google AI SDK for research
try:
    from google import genai
    from google.genai import types
except ImportError:
    print("ERROR: google-genai not installed")
    print("Run: pip install google-genai")
    sys.exit(1)

def diagnose_failure(rule_id: str, metrics: Dict, tests_dir: Path) -> Dict:
    """Analyze integration test failure"""

    tp = metrics['tp']
    fp = metrics['fp']
    tn = metrics['tn']
    fn = metrics['fn']

    #check 1: zero detections (likely field mismatch)
    if tp == 0 and fp == 0:
        #sample first test payload to identify log source
        rule_test_dir = tests_dir / rule_id
        if not rule_test_dir.exists():
            return {'issue': 'no_test_payloads', 'action': 'skip'}

        sample_file = next(rule_test_dir.glob('*.json'), None)
        if not sample_file:
            return {'issue': 'no_test_payloads', 'action': 'skip'}

        with open(sample_file) as f:
            sample = json.load(f)

        log_entry = sample.get('log_entry', sample)
        fields = list(log_entry.keys())

        return {
            'issue': 'field_mismatch',
            'action': 'research_and_convert',
            'confidence': 0.90,
            'details': f'Zero detections - likely field name mismatch',
            'sample_fields': fields[:15],
            'sample_payload': log_entry
        }

    #check 2: high false negatives
    if fn > tp and tp > 0:
        return {
            'issue': 'rule_too_strict',
            'action': 'research_evasion_techniques',
            'confidence': 0.75,
            'details': f'{fn} false negatives vs {tp} true positives'
        }

    #check 3: high false positives
    if fp > tp and tp > 0:
        return {
            'issue': 'rule_too_broad',
            'action': 'research_legitimate_uses',
            'confidence': 0.80,
            'details': f'{fp} false positives vs {tp} true positives'
        }

    return {
        'issue': 'unknown',
        'action': 'manual_review',
        'confidence': 0.0
    }

def research_field_mapping(sample_fields: List[str], sample_payload: Dict,
                          rule_title: str, client: genai.Client) -> Dict:
    """Use LLM + Google Search to research field mapping"""

    print(f"\n  [Research Phase 1] Identifying log source...")

    #prompt to identify log source
    identify_prompt = f"""You are a log analysis expert. Identify the log source format.

**Sample fields from test payload:**
{json.dumps(sample_fields, indent=2)}

**Sample payload snippet:**
{json.dumps(sample_payload, indent=2)[:500]}

**Detection rule context:**
Rule title: {rule_title}

**Your task:**
1. Identify the log source format (Sysmon, Windows Security Event Log, AWS CloudTrail, etc.)
2. Identify the event type (process creation, file creation, network connection, etc.)
3. Provide search queries to research this log format and ECS mapping

**Output as JSON:**
{{
  "log_source": "Sysmon",
  "event_type": "Process Creation (Event ID 1)",
  "confidence": 0.95,
  "reasoning": "Fields like Image, CommandLine, ParentImage are Sysmon-specific",
  "search_queries": [
    "Sysmon Event ID 1 field reference",
    "Elastic Common Schema process fields",
    "map Sysmon to ECS fields"
  ]
}}
"""

    response = client.models.generate_content(
        model='gemini-2.0-flash-exp',
        contents=identify_prompt,
        config=types.GenerateContentConfig(
            temperature=0.1,  #low temp for deterministic analysis
            top_p=0.95,  #focus on high-probability tokens
            top_k=40,  #limit to top 40 tokens
            response_mime_type='application/json',
            thinking_config=types.ThinkingConfig(
                mode=types.ThinkingMode.THINKING_MODE_ENABLED,
                budget_tokens=2000  #~1000 words of reasoning
            )
        )
    )

    identification = json.loads(response.text)
    print(f"  ✓ Identified: {identification['log_source']} - {identification['event_type']}")
    print(f"    Confidence: {identification['confidence']:.0%}")

    #phase 2: research using Google Search
    print(f"\n  [Research Phase 2] Searching documentation...")

    search_results = []
    for query in identification['search_queries'][:2]:  #limit to 2 searches
        print(f"    Searching: {query}")

        search_response = client.models.generate_content(
            model='gemini-2.0-flash-exp',
            contents=f"Search and summarize: {query}",
            config=types.GenerateContentConfig(
                tools=[types.Tool(google_search=types.GoogleSearch())],
                temperature=0.2,  #slightly higher for creative search
                top_p=0.9,
                thinking_config=types.ThinkingConfig(
                    mode=types.ThinkingMode.THINKING_MODE_ENABLED,
                    budget_tokens=1000  #lighter reasoning for search
                )
            )
        )

        search_results.append({
            'query': query,
            'findings': search_response.text[:1000]  #truncate for context
        })

    print(f"  ✓ Gathered {len(search_results)} research sources")

    #phase 3: generate field mapping
    print(f"\n  [Research Phase 3] Generating field mapping...")

    mapping_prompt = f"""You are a field mapping expert. Generate a conversion mapping.

**Log Source:** {identification['log_source']}
**Event Type:** {identification['event_type']}

**Sample Fields:**
{json.dumps(sample_fields, indent=2)}

**Research Findings:**
{json.dumps(search_results, indent=2)}

**Your task:**
Generate a field mapping from {identification['log_source']} to Elastic Common Schema (ECS).

**Requirements:**
1. Map each source field to its ECS equivalent
2. Handle nested ECS fields (e.g., process.executable)
3. Include data type conversions if needed
4. Note any unmapped fields

**Output as JSON:**
{{
  "source_format": "Sysmon Event ID 1",
  "target_format": "ECS 8.x",
  "field_mappings": {{
    "Image": {{
      "ecs_field": "process.executable",
      "type": "keyword",
      "also_extract": {{"process.name": "basename"}}
    }},
    "CommandLine": {{"ecs_field": "process.command_line", "type": "text"}},
    "EventID": {{"ecs_field": "event.code", "type": "keyword"}},
    ...
  }},
  "unmapped_fields": ["SourceField1", "SourceField2"],
  "notes": "Additional context about mapping decisions"
}}

**IMPORTANT**: If mapping a full path field (like Image) to process.executable, also extract process.name (basename).
"""

    mapping_response = client.models.generate_content(
        model='gemini-2.0-flash-exp',
        contents=mapping_prompt,
        config=types.GenerateContentConfig(
            temperature=0.05,  #very low for precise mappings
            top_p=0.95,
            top_k=20,  #stricter sampling for accuracy
            response_mime_type='application/json',
            thinking_config=types.ThinkingConfig(
                mode=types.ThinkingMode.THINKING_MODE_ENABLED,
                budget_tokens=3000  #more reasoning for complex mappings
            )
        )
    )

    mapping = json.loads(mapping_response.text)
    print(f"  ✓ Generated mapping for {len(mapping['field_mappings'])} fields")

    return {
        'identification': identification,
        'research': search_results,
        'mapping': mapping
    }

def apply_field_mapping(tests_dir: Path, rule_id: str, mapping: Dict,
                       backup_dir: Path) -> int:
    """Apply researched field mapping to test payloads"""

    rule_test_dir = tests_dir / rule_id
    if not rule_test_dir.exists():
        return 0

    #backup
    backup_rule_dir = backup_dir / rule_id
    backup_rule_dir.mkdir(parents=True, exist_ok=True)

    converted_count = 0
    field_mappings = mapping['field_mappings']

    for payload_file in rule_test_dir.glob('*.json'):
        #backup
        import shutil
        shutil.copy(payload_file, backup_rule_dir / payload_file.name)

        #load
        with open(payload_file) as f:
            payload = json.load(f)

        if 'log_entry' not in payload:
            continue

        #convert
        original = payload['log_entry']
        converted = {}

        for source_field, value in original.items():
            if source_field in field_mappings:
                ecs_info = field_mappings[source_field]
                ecs_field = ecs_info['ecs_field']

                #handle nested fields
                if '.' in ecs_field:
                    parts = ecs_field.split('.')
                    current = converted
                    for part in parts[:-1]:
                        if part not in current:
                            current[part] = {}
                        current = current[part]
                    current[parts[-1]] = value
                else:
                    converted[ecs_field] = value

                #handle "also_extract" (e.g., process.name from process.executable)
                if 'also_extract' in ecs_info:
                    import os
                    for extract_field, extract_type in ecs_info['also_extract'].items():
                        if extract_type == 'basename':
                            #extract filename from path
                            extracted_value = os.path.basename(value) if isinstance(value, str) else value

                            if '.' in extract_field:
                                parts = extract_field.split('.')
                                current = converted
                                for part in parts[:-1]:
                                    if part not in current:
                                        current[part] = {}
                                    current = current[part]
                                current[parts[-1]] = extracted_value
                            else:
                                converted[extract_field] = extracted_value

            else:
                #keep unmapped fields
                converted[source_field] = value

        payload['log_entry'] = converted

        #save
        with open(payload_file, 'w') as f:
            json.dump(payload, f, indent=2)

        converted_count += 1

    return converted_count

def main():
    import argparse

    parser = argparse.ArgumentParser(description='Intelligent refinement with research')
    parser.add_argument('--results', default='generated/INTEGRATION_TEST_RESULTS.json')
    parser.add_argument('--rules', default='generated/sigma_rules')
    parser.add_argument('--tests', default='generated/tests')
    parser.add_argument('--attempt', type=int, default=1)
    parser.add_argument('--output', default='generated/REFINEMENT_REPORT_V2.json')
    args = parser.parse_args()

    #check GCP credentials
    project_id = os.getenv('GOOGLE_CLOUD_PROJECT')
    if not project_id:
        print("ERROR: GOOGLE_CLOUD_PROJECT not set")
        return 1

    print(f"{'='*80}")
    print(f"INTELLIGENT REFINEMENT - ATTEMPT {args.attempt}/2")
    print(f"Using Gemini Flash + Google Search for dynamic field mapping")
    print(f"{'='*80}\n")

    #initialize client
    client = genai.Client(
        vertexai=True,
        project=project_id,
        location=os.getenv('GOOGLE_CLOUD_LOCATION', 'us-central1')
    )

    #load results
    results_path = Path(args.results)
    if not results_path.exists():
        print(f"ERROR: Results not found: {results_path}")
        return 1

    with open(results_path) as f:
        results = json.load(f)

    if isinstance(results, dict) and results.get('status') == 'skipped':
        print("⚠️  Tests were skipped - nothing to refine")
        return 0

    tests_dir = Path(args.tests)
    backup_dir = Path('generated/tests_backup_v2')
    refinements = []

    #process each failed rule
    for rule_id, metrics in results.items():
        f1_score = metrics['f1_score']

        if f1_score >= 0.75:
            print(f"✓ {metrics['rule_title']}: F1={f1_score:.2f} (PASS)\n")
            continue

        print(f"⚠ {metrics['rule_title']}: F1={f1_score:.2f} (FAIL)")
        print(f"  TP={metrics['tp']}, FP={metrics['fp']}, TN={metrics['tn']}, FN={metrics['fn']}\n")

        #diagnose
        diagnosis = diagnose_failure(rule_id, metrics, tests_dir)

        print(f"  Issue: {diagnosis['issue']}")
        print(f"  Action: {diagnosis['action']}")

        if diagnosis['action'] == 'research_and_convert':
            #research field mapping
            research_result = research_field_mapping(
                diagnosis['sample_fields'],
                diagnosis['sample_payload'],
                metrics['rule_title'],
                client
            )

            #apply mapping
            print(f"\n  [Apply] Converting test payloads...")
            converted = apply_field_mapping(
                tests_dir, rule_id,
                research_result['mapping'],
                backup_dir
            )

            print(f"  ✓ Converted {converted} payloads\n")

            refinements.append({
                'rule_id': rule_id,
                'rule_title': metrics['rule_title'],
                'diagnosis': diagnosis,
                'research': research_result,
                'payloads_converted': converted,
                'timestamp': datetime.now().isoformat()
            })

    #save report
    report = {
        'attempt': args.attempt,
        'timestamp': datetime.now().isoformat(),
        'refinements': refinements,
        'backup_location': str(backup_dir)
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(exist_ok=True, parents=True)
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"{'='*80}")
    print(f"REFINEMENT COMPLETE")
    print(f"{'='*80}")
    print(f"  Rules refined: {len(refinements)}")
    print(f"  Report: {output_path}")
    print(f"  Backup: {backup_dir}\n")

    if refinements:
        print("✓ Re-run integration tests to validate")
        return 0
    else:
        print("⚠ No refinements applied")
        return 1

if __name__ == '__main__':
    sys.exit(main())
