#!/usr/bin/env python3
"""execute detection rule tests against Elasticsearch

reads detection rules, ingests test payloads, executes queries, calculates metrics
"""
import json
import yaml
import time
from pathlib import Path
from typing import Dict, List
from elasticsearch import Elasticsearch
import argparse

def load_rule(rule_path: Path) -> Dict:
    """load detection rule from YAML"""
    with open(rule_path, 'r') as f:
        return yaml.safe_load(f)

def ingest_test_payload(es: Elasticsearch, index: str, log_entry: Dict) -> str:
    """ingest single test payload into ES"""
    response = es.index(
        index=index,
        document=log_entry,
        refresh='wait_for'  #wait for indexing to complete
    )
    return response['_id']

def execute_query(es: Elasticsearch, index: str, lucene_query: str) -> List[Dict]:
    """execute Lucene query against ES and return matching docs"""
    response = es.search(
        index=index,
        query={
            'query_string': {
                'query': lucene_query
            }
        },
        size=100
    )
    return response['hits']['hits']

def calculate_metrics(results: Dict) -> Dict:
    """calculate detection metrics from test results"""
    tp = results.get('TP', 0)
    fn = results.get('FN', 0)
    fp = results.get('FP', 0)
    tn = results.get('TN', 0)

    total = tp + fn + fp + tn

    #precision: tp / (tp + fp)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0

    #recall: tp / (tp + fn)
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

    #f1 score: 2 * (precision * recall) / (precision + recall)
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    #accuracy: (tp + tn) / total
    accuracy = (tp + tn) / total if total > 0 else 0.0

    return {
        'TP': tp,
        'FN': fn,
        'FP': fp,
        'TN': tn,
        'total': total,
        'precision': round(precision, 3),
        'recall': round(recall, 3),
        'f1_score': round(f1, 3),
        'accuracy': round(accuracy, 3)
    }

def test_rule(es: Elasticsearch, rule: Dict, rule_name: str) -> Dict:
    """test single detection rule against all test cases"""
    print(f"\n{'='*80}")
    print(f"Testing: {rule_name}")
    print(f"{'='*80}")

    query = rule.get('query', '')
    test_cases = rule.get('test_cases', [])

    if not query:
        print("  ✗ No query field found")
        return None

    if not test_cases:
        print("  ⚠️  No test cases found")
        return None

    print(f"Query: {query}")
    print(f"Test cases: {len(test_cases)}")

    #create test index
    index_name = f"test-{rule_name.lower().replace(' ', '-').replace('_', '-')}"

    results = {'TP': 0, 'FN': 0, 'FP': 0, 'TN': 0}
    details = []

    for i, test_case in enumerate(test_cases):
        test_type = test_case.get('type', 'UNKNOWN')
        description = test_case.get('description', 'No description')
        log_entry = test_case.get('log_entry', {})
        expected_match = test_case.get('expected_match', False)

        print(f"\n  Test {i+1}/{len(test_cases)} ({test_type}): {description}")

        #ingest test payload
        try:
            doc_id = ingest_test_payload(es, index_name, log_entry)
            print(f"    ✓ Ingested: {doc_id}")
        except Exception as e:
            print(f"    ✗ Ingest failed: {e}")
            continue

        #wait a bit for indexing
        time.sleep(0.5)

        #execute query
        try:
            matches = execute_query(es, index_name, query)
            actual_match = len(matches) > 0
            print(f"    Query matches: {len(matches)}")
        except Exception as e:
            print(f"    ✗ Query failed: {e}")
            continue

        #compare expected vs actual
        if expected_match and actual_match:
            print(f"    ✓ TRUE POSITIVE (expected match, got match)")
            results['TP'] += 1
            outcome = 'TP'
        elif expected_match and not actual_match:
            print(f"    ✗ FALSE NEGATIVE (expected match, NO match)")
            results['FN'] += 1
            outcome = 'FN'
        elif not expected_match and actual_match:
            print(f"    ⚠️  FALSE POSITIVE (expected NO match, got match)")
            results['FP'] += 1
            outcome = 'FP'
        else:  #not expected_match and not actual_match
            print(f"    ✓ TRUE NEGATIVE (expected NO match, NO match)")
            results['TN'] += 1
            outcome = 'TN'

        details.append({
            'test_num': i+1,
            'test_type': test_type,
            'description': description,
            'expected_match': expected_match,
            'actual_match': actual_match,
            'outcome': outcome
        })

    #calculate metrics
    metrics = calculate_metrics(results)

    print(f"\n{'='*80}")
    print(f"Results for {rule_name}:")
    print(f"  TP: {metrics['TP']}  FN: {metrics['FN']}  FP: {metrics['FP']}  TN: {metrics['TN']}")
    print(f"  Precision: {metrics['precision']:.1%}")
    print(f"  Recall: {metrics['recall']:.1%}")
    print(f"  F1 Score: {metrics['f1_score']:.3f}")
    print(f"  Accuracy: {metrics['accuracy']:.1%}")

    return {
        'rule_name': rule_name,
        'query': query,
        'results': results,
        'metrics': metrics,
        'details': details
    }

def main():
    parser = argparse.ArgumentParser(description='Execute detection rule tests against Elasticsearch')
    parser.add_argument('--rules-dir', required=True, help='Directory containing detection rule YAML files')
    parser.add_argument('--es-url', default='http://localhost:9200', help='Elasticsearch URL')
    args = parser.parse_args()

    #connect to ES
    print(f"Connecting to Elasticsearch at {args.es_url}...")
    es = Elasticsearch([args.es_url])

    #check ES health
    try:
        health = es.cluster.health()
        print(f"✓ Elasticsearch status: {health['status']}")
    except Exception as e:
        print(f"✗ Elasticsearch connection failed: {e}")
        return 1

    #load all rules
    rules_dir = Path(args.rules_dir)
    rule_files = list(rules_dir.glob('*.yml'))

    if not rule_files:
        print(f"✗ No rule files found in {rules_dir}")
        return 1

    print(f"\nFound {len(rule_files)} rules to test")

    all_results = []

    for rule_file in rule_files:
        rule_name = rule_file.stem
        rule = load_rule(rule_file)

        result = test_rule(es, rule, rule_name)
        if result:
            all_results.append(result)

    #summary
    print(f"\n{'='*80}")
    print(f"SUMMARY - Tested {len(all_results)} rules")
    print(f"{'='*80}")

    total_tp = sum(r['results']['TP'] for r in all_results)
    total_fn = sum(r['results']['FN'] for r in all_results)
    total_fp = sum(r['results']['FP'] for r in all_results)
    total_tn = sum(r['results']['TN'] for r in all_results)

    overall_metrics = calculate_metrics({
        'TP': total_tp,
        'FN': total_fn,
        'FP': total_fp,
        'TN': total_tn
    })

    print(f"\nOverall Metrics:")
    print(f"  Total Tests: {overall_metrics['total']}")
    print(f"  TP: {overall_metrics['TP']}  FN: {overall_metrics['FN']}  FP: {overall_metrics['FP']}  TN: {overall_metrics['TN']}")
    print(f"  Precision: {overall_metrics['precision']:.1%}")
    print(f"  Recall: {overall_metrics['recall']:.1%}")
    print(f"  F1 Score: {overall_metrics['f1_score']:.3f}")
    print(f"  Accuracy: {overall_metrics['accuracy']:.1%}")

    #save detailed results
    results_file = Path('test_results.json')
    with open(results_file, 'w') as f:
        json.dump({
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'rules_tested': len(all_results),
            'overall_metrics': overall_metrics,
            'rule_results': all_results
        }, f, indent=2)

    print(f"\n✓ Detailed results saved to {results_file}")

    return 0

if __name__ == '__main__':
    exit(main())
