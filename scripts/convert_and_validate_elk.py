#!/usr/bin/env python3
"""
Sigma → ELK Converter + Validator

Uses Gemini 2.5 Pro to:
1. Convert Sigma rules to Elasticsearch DSL queries
2. Research/validate against official Elasticsearch documentation
3. Check query syntax and compatibility
4. Generate validated queries ready for integration testing

This step happens BEFORE integration testing to catch syntax errors early.
"""

import json
import yaml
import sys
import os
from pathlib import Path
from typing import Dict, List
from datetime import datetime

try:
    from sigma.rule import SigmaRule
    from sigma.backends.elasticsearch import LuceneBackend
    from sigma.pipelines.elasticsearch import ecs_windows
except ImportError:
    print("ERROR: pysigma libraries not installed")
    print("Run: pip install pysigma pysigma-backend-elasticsearch")
    sys.exit(1)

try:
    from google import genai
    from google.genai import types
except ImportError:
    print("ERROR: google-genai not installed")
    print("Run: pip install google-genai")
    sys.exit(1)

VALIDATION_PROMPT = """You are an Elasticsearch query expert.

Given a Sigma detection rule and its automatically converted Elasticsearch DSL query, validate:

1. **Syntax Correctness**: Is the Elasticsearch query syntactically valid?
2. **Field Mapping**: Do field names match standard log schemas (ECS, Windows Event, etc.)?
3. **Query Logic**: Does the query accurately represent the Sigma detection logic?
4. **Performance**: Are there any obvious performance issues (e.g., wildcard at start)?
5. **Compatibility**: Is this compatible with Elasticsearch 8.x?

Research official Elasticsearch documentation if needed.

Output JSON:
{
  "valid": true|false,
  "syntax_score": 0.0-1.0,
  "field_mapping_score": 0.0-1.0,
  "logic_accuracy_score": 0.0-1.0,
  "performance_score": 0.0-1.0,
  "overall_score": 0.0-1.0,
  "issues": ["issue 1", "issue 2"],
  "warnings": ["warning 1"],
  "recommendations": ["fix 1"],
  "decision": "APPROVE|REJECT"
}

APPROVE if overall_score >= 0.80 and no critical syntax errors.
REJECT if syntax invalid or critical field mapping errors.
"""

def convert_sigma_to_elk(sigma_rule_path: Path) -> Dict:
    """convert sigma rule to elasticsearch DSL using pysigma"""
    try:
        #load sigma rule
        with open(sigma_rule_path) as f:
            rule_yaml = yaml.safe_load(f)

        rule = SigmaRule.from_yaml(sigma_rule_path)

        #convert to elasticsearch lucene format
        backend = LuceneBackend()
        queries = backend.convert_rule(rule)

        #get first query (rules can produce multiple queries)
        if isinstance(queries, list):
            elk_query = queries[0] if queries else ""
        else:
            elk_query = str(queries)

        return {
            'success': True,
            'rule_id': str(rule_yaml.get('id')),
            'rule_title': rule_yaml.get('title'),
            'sigma_detection': rule_yaml.get('detection'),
            'elk_lucene_query': elk_query,
            'elk_dsl_query': {
                'query': {
                    'query_string': {
                        'query': elk_query
                    }
                }
            }
        }

    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'rule_file': str(sigma_rule_path)
        }

def validate_elk_query(conversion: Dict, client, model_name: str) -> Dict:
    """validate ELK query using Gemini with Google Search grounding"""

    if not conversion.get('success'):
        return {
            'valid': False,
            'overall_score': 0.0,
            'decision': 'REJECT',
            'issues': [f"Conversion failed: {conversion.get('error')}"]
        }

    rule_id = conversion.get('rule_id')
    rule_title = conversion.get('rule_title')
    sigma_detection = conversion.get('sigma_detection')
    elk_query = conversion.get('elk_lucene_query')
    elk_dsl = conversion.get('elk_dsl_query')

    prompt = f"""{VALIDATION_PROMPT}

**Sigma Rule:**
Title: {rule_title}
ID: {rule_id}

Sigma Detection Logic:
```yaml
{yaml.dump(sigma_detection, default_flow_style=False)}
```

**Generated Elasticsearch Query:**

Lucene Query String:
```
{elk_query}
```

Elasticsearch DSL:
```json
{json.dumps(elk_dsl, indent=2)}
```

Validate this conversion and provide your assessment in JSON format.
Research Elasticsearch 8.x documentation if needed to verify syntax and field compatibility.
"""

    print(f"  Validating: {rule_title[:60]}...")

    try:
        #use Gemini with Google Search for documentation research
        response = client.models.generate_content(
            model=model_name,
            contents=prompt,
            config=types.GenerateContentConfig(
                tools=[types.Tool(google_search=types.GoogleSearch())]
            )
        )

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

        validation = json.loads(json_text)

        #add grounding metadata if available
        if hasattr(response, 'grounding_metadata'):
            validation['grounding_sources'] = str(response.grounding_metadata)

        return validation

    except json.JSONDecodeError as e:
        print(f"    ⚠ Warning: Could not parse validation response")
        return {
            'valid': False,
            'overall_score': 0.0,
            'decision': 'REJECT',
            'issues': ['Failed to parse LLM validation response'],
            'error': str(e)
        }

    except Exception as e:
        print(f"    ✗ Error: {e}")
        return {
            'valid': False,
            'overall_score': 0.0,
            'decision': 'REJECT',
            'issues': [f'Validation error: {str(e)}']
        }

def main():
    import argparse

    parser = argparse.ArgumentParser(description='Convert and validate Sigma → ELK')
    parser.add_argument('--rules', default='generated/sigma_rules', help='Sigma rules directory')
    parser.add_argument('--output', default='generated/ELK_QUERIES.json', help='Output validated queries file')
    parser.add_argument('--validation-report', default='generated/ELK_VALIDATION_REPORT.json', help='Validation report')
    parser.add_argument('--project', help='GCP project ID')
    parser.add_argument('--location', default='us-central1', help='GCP region')
    args = parser.parse_args()

    rules_dir = Path(args.rules)
    output_file = Path(args.output)
    validation_report_file = Path(args.validation_report)

    if not rules_dir.exists():
        print(f"ERROR: Rules directory not found: {rules_dir}")
        return 1

    #setup Vertex AI
    project_id = args.project or os.environ.get('GOOGLE_CLOUD_PROJECT')

    if not project_id:
        print("ERROR: GCP project ID not provided")
        return 1

    #enable Vertex AI mode
    os.environ['GOOGLE_GENAI_USE_VERTEXAI'] = 'true'

    print(f"Using Vertex AI: {project_id} ({args.location})")
    client = genai.Client(
        vertexai=True,
        project=project_id,
        location=args.location
    )

    #use Gemini 2.5 Pro for research + validation
    model_name = 'gemini-2.5-pro'

    print(f"\n{'='*80}")
    print("SIGMA → ELASTICSEARCH CONVERTER + VALIDATOR")
    print(f"{'='*80}\n")

    #load sigma rules
    print("[1/3] Converting Sigma rules to Elasticsearch...")
    rule_files = list(rules_dir.glob('*.yml')) + list(rules_dir.glob('*.yaml'))
    print(f"  Found {len(rule_files)} Sigma rules")

    conversions = []

    for rule_file in rule_files:
        print(f"  Converting: {rule_file.name}")
        conversion = convert_sigma_to_elk(rule_file)
        conversions.append(conversion)

    successful_conversions = [c for c in conversions if c.get('success')]
    print(f"\n  ✓ Successfully converted {len(successful_conversions)}/{len(conversions)} rules")

    #validate conversions with Gemini
    print(f"\n[2/3] Validating ELK queries with Gemini 2.5 Pro + Google Search...")
    validations = []

    for conversion in successful_conversions:
        validation = validate_elk_query(conversion, client, model_name)
        validation['rule_id'] = conversion.get('rule_id')
        validation['rule_title'] = conversion.get('rule_title')
        validations.append(validation)

    approved_count = sum(1 for v in validations if v.get('decision') == 'APPROVE')
    print(f"\n  ✓ Validated {len(validations)} queries")
    print(f"  ✅ Approved: {approved_count}")
    print(f"  ❌ Rejected: {len(validations) - approved_count}")

    #save validated queries
    print(f"\n[3/3] Saving validated ELK queries...")

    elk_queries = {}

    for i, conversion in enumerate(successful_conversions):
        validation = validations[i]

        if validation.get('decision') == 'APPROVE':
            rule_id = conversion.get('rule_id')

            elk_queries[rule_id] = {
                'rule_title': conversion.get('rule_title'),
                'lucene_query': conversion.get('elk_lucene_query'),
                'dsl_query': conversion.get('elk_dsl_query'),
                'validation_score': validation.get('overall_score'),
                'validated': True
            }

    output_file.parent.mkdir(exist_ok=True, parents=True)
    with open(output_file, 'w') as f:
        json.dump(elk_queries, f, indent=2)

    print(f"  ✓ Saved {len(elk_queries)} validated queries to: {output_file}")

    #save validation report
    validation_report = {
        'timestamp': datetime.now().isoformat(),
        'total_rules': len(rule_files),
        'successful_conversions': len(successful_conversions),
        'approved_queries': approved_count,
        'rejected_queries': len(validations) - approved_count,
        'validations': validations
    }

    validation_report_file.parent.mkdir(exist_ok=True, parents=True)
    with open(validation_report_file, 'w') as f:
        json.dump(validation_report, f, indent=2)

    print(f"  ✓ Saved validation report to: {validation_report_file}")

    #summary
    print(f"\n{'='*80}")
    print("CONVERSION + VALIDATION SUMMARY")
    print(f"{'='*80}\n")
    print(f"Total Sigma Rules: {len(rule_files)}")
    print(f"Successful Conversions: {len(successful_conversions)}")
    print(f"Approved for Integration Testing: {approved_count}")
    print(f"Rejected (need fixes): {len(validations) - approved_count}")
    print(f"\n{'='*80}\n")

    if approved_count > 0:
        print(f"✅ {approved_count} ELK queries ready for integration testing")
        return 0
    else:
        print("❌ No queries approved - all need fixes")
        return 1

if __name__ == '__main__':
    sys.exit(main())
