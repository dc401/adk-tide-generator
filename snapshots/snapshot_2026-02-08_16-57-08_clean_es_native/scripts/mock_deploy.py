#!/usr/bin/env python3
"""mock SIEM deployment with ephemeral Elasticsearch"""
import json
import yaml
import time
import os
from pathlib import Path
from elasticsearch import Elasticsearch
from sigma.rule import SigmaRule
from sigma.backends.elasticsearch import LuceneBackend

print("\n" + "="*80)
print("MOCK PRODUCTION SIEM DEPLOYMENT")
print("="*80 + "\n")

#connect to elasticsearch (mock SIEM)
es = Elasticsearch(['http://localhost:9200'])

#load staged rules
staged_rules_dir = Path('staged_rules')

if not staged_rules_dir.exists():
    print("ERROR: No staged_rules directory found")
    exit(1)

rule_files = list(staged_rules_dir.glob('*.yml')) + list(staged_rules_dir.glob('*.yaml'))

if not rule_files:
    print("ERROR: No rules found in staged_rules/")
    exit(1)

print(f"Found {len(rule_files)} rules to deploy\n")

#deploy each rule to elasticsearch
backend = LuceneBackend()
deployed_rules = []

for rule_file in rule_files:
    with open(rule_file) as f:
        rule_yaml = yaml.safe_load(f)

    rule = SigmaRule.from_yaml(rule_file)
    elk_query = backend.convert_rule(rule)

    #create detection rule in elasticsearch
    rule_id = rule_yaml.get('id')
    rule_title = rule_yaml.get('title')

    #in real deployment, this would use the SIEM's native detection rule API
    #for Elasticsearch, this would be the Detection Rules API
    detection_rule = {
        'name': rule_title,
        'description': rule_yaml.get('description'),
        'severity': rule_yaml.get('level', 'medium'),
        'risk_score': 50,
        'type': 'query',
        'query': elk_query,
        'interval': '5m',
        'tags': rule_yaml.get('tags', []),
        'enabled': True,
        'metadata': {
            'rule_id': rule_id,
            'deployed_by': 'github-actions',
            'deployment_type': 'mock',
            'batch': 'staged_rules'
        }
    }

    #save to elasticsearch (mock deployment)
    es.index(
        index='.detection-rules',
        id=rule_id,
        document=detection_rule
    )

    deployed_rules.append({
        'rule_id': rule_id,
        'title': rule_title,
        'file': rule_file.name
    })

    print(f"✓ Deployed: {rule_title}")

#wait for indexing
time.sleep(2)

#verify deployment
deployed_count = es.count(index='.detection-rules')['count']

print(f"\n" + "="*80)
print("DEPLOYMENT SUMMARY")
print("="*80 + "\n")
print(f"Rules Deployed: {len(deployed_rules)}")
print(f"Verified in SIEM: {deployed_count}")
print(f"\nDeployment Type: MOCK (ephemeral Elasticsearch)")
print("In production, these rules would be deployed to:")
print("  - Splunk → SPL queries")
print("  - Chronicle → YARA-L 2.0")
print("  - Sentinel → KQL queries")
print("  - Elastic → Elasticsearch DSL")
print(f"\n" + "="*80 + "\n")

#save deployment manifest
os.makedirs('production_rules', exist_ok=True)

manifest = {
    'deployed_at': time.strftime('%Y-%m-%d %H:%M:%S'),
    'pr_number': os.environ.get('PR_NUMBER', 'unknown'),
    'approved_by': os.environ.get('APPROVED_BY', 'unknown'),
    'rules': deployed_rules
}

with open('production_rules/DEPLOYMENT_MANIFEST.json', 'w') as f:
    json.dump(manifest, f, indent=2)

print("✓ Saved deployment manifest")
