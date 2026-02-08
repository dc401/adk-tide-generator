#!/usr/bin/env python3
"""
Integration test for CI/CD with pre-existing Elasticsearch

Assumes Elasticsearch is already running (via GitHub Actions services or docker-compose).
Does NOT manage Docker containers - only runs tests.
"""

import json
import time
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List

try:
    from elasticsearch import Elasticsearch
    from elasticsearch.exceptions import ConnectionError as ESConnectionError
except ImportError:
    print("ERROR: elasticsearch library not installed")
    print("Run: pip install elasticsearch")
    sys.exit(1)

import yaml
import ssl
import requests
ssl._create_default_https_context = ssl._create_unverified_context

from sigma.rule import SigmaRule
from sigma.backends.elasticsearch import LuceneBackend

def wait_for_elasticsearch(url: str = 'http://localhost:9200', timeout: int = 60) -> bool:
    """wait for Elasticsearch to be ready"""
    print(f"\n[1/5] Waiting for Elasticsearch at {url}...")

    start_time = time.time()
    last_log = 0

    while time.time() - start_time < timeout:
        try:
            response = requests.get(f'{url}/_cluster/health', timeout=3)
            if response.status_code == 200:
                health = response.json()
                status = health.get('status', 'unknown')
                elapsed = int(time.time() - start_time)
                print(f"  ✓ Elasticsearch ready after {elapsed}s (status: {status})")
                return True
        except Exception:
            current = time.time()
            if current - last_log >= 5:
                print(f"  Waiting... {int(current - start_time)}s", flush=True)
                last_log = current

        time.sleep(2)

    print(f"  ✗ Elasticsearch not ready after {timeout}s")
    return False

def convert_sigma_to_elasticsearch(rules_dir: Path) -> Dict:
    """convert Sigma rules to Elasticsearch queries"""
    print("\n[2/5] Converting Sigma rules to Elasticsearch queries...")

    backend = LuceneBackend()
    queries = {}

    rule_files = list(rules_dir.glob('*.yml')) + list(rules_dir.glob('*.yaml'))

    for rule_file in rule_files:
        with open(rule_file) as f:
            rule = SigmaRule.from_yaml(f)

        lucene_queries = backend.convert_rule(rule)
        lucene_query = '\n'.join(lucene_queries) if isinstance(lucene_queries, list) else str(lucene_queries)

        queries[str(rule.id)] = {
            'title': rule.title,
            'query': lucene_query,
            'level': rule.level.name,
            'file': rule_file.name
        }

    print(f"  ✓ Converted {len(queries)} Sigma rules")
    return queries

def ingest_test_payloads(es: Elasticsearch, tests_dir: Path) -> Dict:
    """ingest test payloads into Elasticsearch"""
    print("\n[3/5] Ingesting test payloads...")

    index_name = "test-logs"

    #create index (delete if exists)
    try:
        if es.indices.exists(index=index_name):
            es.indices.delete(index=index_name)
    except Exception:
        pass  #index doesn't exist, that's fine

    es.indices.create(
        index=index_name,
        mappings={
            "properties": {
                "timestamp": {"type": "date"},
                "protoPayload": {"type": "object", "enabled": True},
                "resource": {"type": "object", "enabled": True},
                "_scenario": {"type": "keyword"},
                "_expected_detection": {"type": "boolean"}
            }
        }
    )

    payload_map = {}
    total_ingested = 0

    for rule_dir in sorted(tests_dir.iterdir()):
        if not rule_dir.is_dir():
            continue

        payload_map[rule_dir.name] = []
        print(f"\n  Rule: {rule_dir.name}")

        for payload_file in rule_dir.glob('*.json'):
            with open(payload_file) as f:
                payload = json.load(f)

            doc_id = f"{rule_dir.name}_{payload_file.stem}"

            #show what we're indexing
            log_entry = payload.get('log_entry', payload)
            field_sample = list(log_entry.keys())[:5] if isinstance(log_entry, dict) else []
            print(f"    • {payload_file.stem}: fields={field_sample}")

            #ingest ONLY log_entry to elasticsearch (not wrapper)
            es.index(index=index_name, id=doc_id, document=log_entry)

            payload_map[rule_dir.name].append({
                'id': doc_id,
                'scenario': payload.get('payload_type'),
                'expected': payload.get('expected_alert')
            })

            total_ingested += 1

    #refresh index to make documents searchable
    es.indices.refresh(index=index_name)

    #verify indexing worked
    count_result = es.count(index=index_name)
    indexed_count = count_result['count']

    print(f"\n  ✓ Ingested {total_ingested} test payloads")
    print(f"  ✓ Elasticsearch reports {indexed_count} documents in '{index_name}' index")

    if indexed_count != total_ingested:
        print(f"  ⚠ WARNING: Mismatch! Sent {total_ingested} but ES has {indexed_count}")

    print("  Waiting 3s for index to stabilize...")
    time.sleep(3)

    return payload_map

def run_detection_queries(es: Elasticsearch, queries: Dict, index_name: str = "test-logs") -> Dict:
    """run Elasticsearch queries and collect matches"""
    print("\n[4/5] Running detection queries...")

    #show index contents first
    count_result = es.count(index=index_name)
    print(f"\n  Index '{index_name}' has {count_result['count']} documents")

    #show sample document structure
    sample_resp = es.search(index=index_name, size=1)
    if sample_resp['hits']['total']['value'] > 0:
        sample_doc = sample_resp['hits']['hits'][0]['_source']
        print(f"  Sample document fields: {list(sample_doc.keys())[:10]}")

    detections = {}

    for rule_id, rule_info in queries.items():
        print(f"\n  Testing: {rule_info['title']}")
        print(f"    Lucene query: {rule_info['query']}")

        query_dsl = {
            "query": {
                "query_string": {
                    "query": rule_info['query'],
                    "default_field": "*",
                    "analyze_wildcard": True,
                    "case_insensitive": True
                }
            },
            "size": 100
        }

        try:
            response = es.search(index=index_name, query=query_dsl['query'], size=query_dsl['size'])
            matched_ids = [hit['_id'] for hit in response['hits']['hits']]

            print(f"    Matched: {len(matched_ids)} documents")
            if matched_ids:
                print(f"      Document IDs: {matched_ids[:5]}")
            else:
                #debug why no matches - try simplified query
                print(f"    (no matches - debugging...)")
                first_field = rule_info['query'].lstrip('(').split(':')[0] if ':' in rule_info['query'] else None
                if first_field:
                    debug_query = f"{first_field}:*"
                    debug_resp = es.search(
                        index=index_name,
                        query={"query_string": {"query": debug_query, "default_field": "*", "case_insensitive": True}},
                        size=5
                    )
                    print(f"      Debug: '{debug_query}' matches {debug_resp['hits']['total']['value']} docs")

            detections[rule_id] = matched_ids

        except Exception as e:
            print(f"    ✗ ERROR running query: {e}")
            detections[rule_id] = []

    total_detections = sum(len(ids) for ids in detections.values())
    print(f"\n  Summary: {total_detections} total matches across {len(queries)} rules")

    return detections

def calculate_metrics(payload_map: Dict, detections: Dict, queries: Dict) -> Dict:
    """calculate precision, recall, F1"""
    print("\n[5/5] Calculating metrics...")

    results = {}

    for rule_dir, payloads in payload_map.items():
        #find matching rule
        rule_id = None
        for rid in queries.keys():
            if rid[:8] in rule_dir:
                rule_id = rid
                break

        if not rule_id:
            continue

        detected_ids = set(detections.get(rule_id, []))

        tp = fp = tn = fn = 0

        for payload_info in payloads:
            doc_id = payload_info['id']
            expected = payload_info['expected']
            detected = doc_id in detected_ids

            if expected and detected:
                tp += 1
            elif not expected and detected:
                fp += 1
            elif not expected and not detected:
                tn += 1
            elif expected and not detected:
                fn += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        results[rule_id] = {
            'rule_title': queries[rule_id]['title'],
            'rule_level': queries[rule_id]['level'],
            'tp': tp,
            'fp': fp,
            'tn': tn,
            'fn': fn,
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score
        }

    print(f"  ✓ Calculated metrics for {len(results)} rules")
    return results

def print_results(results: Dict):
    """print test results"""
    print(f"\n{'='*80}")
    print("CI INTEGRATION TEST RESULTS")
    print(f"{'='*80}\n")

    total_rules = len(results)
    total_tp = sum(r['tp'] for r in results.values())
    total_fp = sum(r['fp'] for r in results.values())
    total_tn = sum(r['tn'] for r in results.values())
    total_fn = sum(r['fn'] for r in results.values())

    avg_precision = sum(r['precision'] for r in results.values()) / total_rules if total_rules > 0 else 0
    avg_recall = sum(r['recall'] for r in results.values()) / total_rules if total_rules > 0 else 0
    avg_f1 = sum(r['f1_score'] for r in results.values()) / total_rules if total_rules > 0 else 0

    print(f"Rules tested: {total_rules}")
    print(f"\nOverall Metrics:")
    print(f"  True Positives:  {total_tp}")
    print(f"  False Positives: {total_fp}")
    print(f"  True Negatives:  {total_tn}")
    print(f"  False Negatives: {total_fn}")
    print(f"\nAverage Performance:")
    print(f"  Precision: {avg_precision:.2f}")
    print(f"  Recall:    {avg_recall:.2f}")
    print(f"  F1 Score:  {avg_f1:.2f}")

    print(f"\n{'='*80}")
    print("PER-RULE RESULTS")
    print(f"{'='*80}\n")

    for rule_id, metrics in sorted(results.items(), key=lambda x: x[1]['f1_score'], reverse=True):
        print(f"{metrics['rule_title']} (Level: {metrics['rule_level']})")
        print(f"  TP: {metrics['tp']}  FP: {metrics['fp']}  TN: {metrics['tn']}  FN: {metrics['fn']}")
        print(f"  Precision: {metrics['precision']:.2f}  Recall: {metrics['recall']:.2f}  F1: {metrics['f1_score']:.2f}")

        if metrics['fp'] > 0:
            print(f"  ⚠ {metrics['fp']} false positive(s)")
        if metrics['fn'] > 0:
            print(f"  ⚠ {metrics['fn']} false negative(s)")

        print()

    print(f"{'='*80}\n")

def main():
    import argparse

    parser = argparse.ArgumentParser(description='CI integration test with Elasticsearch')
    parser.add_argument('--rules', default='generated/sigma_rules',
                       help='Directory containing Sigma rules')
    parser.add_argument('--tests', default='generated/tests',
                       help='Directory containing test payloads')
    parser.add_argument('--es-url', default='http://localhost:9200',
                       help='Elasticsearch URL')
    args = parser.parse_args()

    rules_dir = Path(args.rules)
    tests_dir = Path(args.tests)

    if not rules_dir.exists():
        print(f"ERROR: Rules directory not found: {rules_dir}")
        return 1

    if not tests_dir.exists():
        print(f"WARNING: Tests directory not found: {tests_dir}")
        print("No test payloads to validate - skipping integration test")
        print("Rules can still be deployed but won't have test coverage")

        #create minimal results file for quality gate
        output_path = Path('generated/INTEGRATION_TEST_RESULTS.json')
        output_path.parent.mkdir(exist_ok=True, parents=True)
        with open(output_path, 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'status': 'skipped',
                'reason': 'No test payloads found',
                'rules_tested': 0,
                'total_tests': 0,
                'passed': 0,
                'failed': 0
            }, f, indent=2)
        print(f"✓ Created minimal results file: {output_path}")
        return 0

    print(f"{'='*80}")
    print("SIGMA RULE INTEGRATION TESTING (CI)")
    print(f"{'='*80}")
    print(f"\nRules: {rules_dir}")
    print(f"Tests: {tests_dir}")
    print(f"Elasticsearch: {args.es_url}")

    #wait for elasticsearch
    if not wait_for_elasticsearch(args.es_url):
        return 1

    #create ES client (using elasticsearch-py 8.x for ES 8.12.0 compatibility)
    es = Elasticsearch([args.es_url])

    #convert sigma rules
    queries = convert_sigma_to_elasticsearch(rules_dir)

    #ingest test payloads
    payload_map = ingest_test_payloads(es, tests_dir)

    #run detection queries
    detections = run_detection_queries(es, queries)

    #calculate metrics
    results = calculate_metrics(payload_map, detections, queries)

    #print results
    print_results(results)

    #save results
    output_file = Path('generated/INTEGRATION_TEST_RESULTS.json')
    output_file.parent.mkdir(exist_ok=True, parents=True)
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"Results saved to: {output_file}")

    return 0

if __name__ == '__main__':
    sys.exit(main())
