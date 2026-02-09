#!/usr/bin/env python3
"""ECS schema loader - downloads and caches official Elastic Common Schema"""
import yaml
import requests
from pathlib import Path
from typing import Dict

ECS_SCHEMA_URL = "https://raw.githubusercontent.com/elastic/ecs/main/generated/ecs/ecs_flat.yml"
SCHEMA_CACHE_PATH = Path(__file__).parent.parent / 'schemas' / 'ecs_flat.yml'

def download_ecs_schema() -> Dict:
    """download official ECS schema from Elastic GitHub"""
    print(f"Downloading ECS schema from {ECS_SCHEMA_URL}...")
    
    try:
        response = requests.get(ECS_SCHEMA_URL, timeout=30)
        response.raise_for_status()
        
        schema_yaml = response.text
        
        #cache locally
        SCHEMA_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(SCHEMA_CACHE_PATH, 'w') as f:
            f.write(schema_yaml)
        
        schema = yaml.safe_load(schema_yaml)
        print(f"✓ Downloaded ECS schema ({len(schema)} fields)")
        return schema
        
    except Exception as e:
        print(f"✗ Failed to download ECS schema: {e}")
        return {}

def load_ecs_schema() -> Dict:
    """load cached ECS schema or download if missing"""
    
    #check cache first
    if SCHEMA_CACHE_PATH.exists():
        try:
            with open(SCHEMA_CACHE_PATH) as f:
                schema = yaml.safe_load(f)
            print(f"✓ Loaded cached ECS schema ({len(schema)} fields)")
            return schema
        except Exception as e:
            print(f"⚠️  Failed to load cached schema: {e}")
    
    #download if cache missing or corrupted
    return download_ecs_schema()

def get_field_info(schema: Dict, field_name: str) -> Dict:
    """get information about specific ECS field"""
    if field_name in schema:
        field_data = schema[field_name]
        return {
            'valid': True,
            'field': field_name,
            'type': field_data.get('type', 'unknown'),
            'description': field_data.get('description', ''),
            'example': field_data.get('example', ''),
            'level': field_data.get('level', 'custom')
        }
    
    return {
        'valid': False,
        'field': field_name,
        'error': 'Field not found in ECS schema'
    }

if __name__ == '__main__':
    #test
    schema = load_ecs_schema()
    
    #test common fields
    test_fields = ['event.category', 'process.name', 'process.command_line', 'file.name']
    
    for field in test_fields:
        info = get_field_info(schema, field)
        print(f"\n{field}:")
        print(f"  Valid: {info['valid']}")
        if info['valid']:
            print(f"  Type: {info['type']}")
            print(f"  Description: {info['description'][:80]}...")
