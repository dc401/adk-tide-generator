#!/usr/bin/env python3
"""Lucene query syntax validator using luqum"""
from typing import Dict
import re

def validate_lucene_query(query: str) -> Dict:
    """validate Lucene query syntax"""
    
    try:
        from luqum import parser
        
        #parse query
        tree = parser.parse(query)
        
        return {
            'valid': True,
            'query': query,
            'message': 'Valid Lucene syntax'
        }
        
    except ImportError:
        #luqum not installed, do basic validation
        return basic_lucene_validation(query)
        
    except Exception as e:
        error_msg = str(e)
        
        #extract position if available
        position_match = re.search(r'position (\d+)', error_msg)
        position = int(position_match.group(1)) if position_match else None
        
        #show problematic part
        if position:
            start = max(0, position - 20)
            end = min(len(query), position + 20)
            snippet = query[start:end]
            marker = ' ' * (position - start) + '^'
            
            error_detail = f"{error_msg}\n  {snippet}\n  {marker}"
        else:
            error_detail = error_msg
        
        return {
            'valid': False,
            'query': query,
            'error': error_msg,
            'error_detail': error_detail,
            'position': position
        }

def basic_lucene_validation(query: str) -> Dict:
    """basic Lucene validation without luqum"""
    
    errors = []
    
    #check for unescaped special chars
    special_chars = r'[+\-=&|><!\(\){}\[\]^"~*?:\\\/]'
    
    #check balanced parentheses
    open_count = query.count('(')
    close_count = query.count(')')
    if open_count != close_count:
        errors.append(f"Unbalanced parentheses: {open_count} open, {close_count} close")
    
    #check for literal slashes (common error)
    if re.search(r'\s/[a-zA-Z]', query):
        errors.append("Literal slash detected - use wildcards instead (e.g., *flag* not /flag)")
    
    if errors:
        return {
            'valid': False,
            'query': query,
            'error': '; '.join(errors)
        }
    
    return {
        'valid': True,
        'query': query,
        'message': 'Basic validation passed (install luqum for full validation)'
    }

def extract_fields_from_query(query: str) -> list:
    """extract field names from Lucene query"""
    
    #pattern: field_name:value or field_name:(...)
    pattern = r'([a-zA-Z_][a-zA-Z0-9_\.]*)\s*:'
    
    fields = re.findall(pattern, query)
    
    #deduplicate and sort
    return sorted(set(fields))

if __name__ == '__main__':
    #test
    test_queries = [
        'event.category:process AND process.name:*cmd.exe*',
        'process.command_line:(*stop* /y*)',  #invalid - literal slash
        'event.category:file AND file.name:(test',  #invalid - unbalanced paren
    ]
    
    for q in test_queries:
        print(f"\nQuery: {q}")
        result = validate_lucene_query(q)
        print(f"  Valid: {result['valid']}")
        if not result['valid']:
            print(f"  Error: {result.get('error_detail', result.get('error'))}")
        
        fields = extract_fields_from_query(q)
        print(f"  Fields: {fields}")
