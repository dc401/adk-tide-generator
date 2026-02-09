#!/usr/bin/env python3
"""ECS field validator with dynamic research capability"""
import json
from typing import Dict, List
from pathlib import Path

from detection_agent.tools.ecs_schema_loader import load_ecs_schema, get_field_info

class ECSFieldValidator:
    """validates detection rule fields against ECS schema"""
    
    def __init__(self):
        self.schema = load_ecs_schema()
        self.dynamic_cache = {}  #session cache for researched fields
        self.cache_file = Path(__file__).parent.parent / 'schemas' / 'dynamic_fields_cache.json'
        
        #load persistent cache
        if self.cache_file.exists():
            try:
                with open(self.cache_file) as f:
                    self.dynamic_cache = json.load(f)
                print(f"✓ Loaded {len(self.dynamic_cache)} cached field lookups")
            except:
                pass
    
    def validate_field(self, field_name: str) -> Dict:
        """validate if field exists in ECS schema or cache"""
        
        #check ECS schema first (authoritative)
        info = get_field_info(self.schema, field_name)
        if info['valid']:
            return info
        
        #check dynamic cache (researched fields)
        if field_name in self.dynamic_cache:
            cached = self.dynamic_cache[field_name]
            cached['source'] = 'dynamic_cache'
            return cached
        
        #field unknown - needs research
        return {
            'valid': False,
            'field': field_name,
            'error': 'Field not in ECS schema - requires research',
            'needs_research': True
        }
    
    def validate_fields(self, field_names: List[str]) -> Dict:
        """validate multiple fields"""
        results = {
            'valid_fields': [],
            'invalid_fields': [],
            'needs_research': []
        }
        
        for field in field_names:
            info = self.validate_field(field)
            
            if info['valid']:
                results['valid_fields'].append({
                    'field': field,
                    'type': info.get('type'),
                    'description': info.get('description', '')[:100]
                })
            elif info.get('needs_research'):
                results['needs_research'].append(field)
            else:
                results['invalid_fields'].append({
                    'field': field,
                    'error': info.get('error')
                })
        
        return results
    
    def cache_field(self, field_name: str, field_info: Dict):
        """cache researched field for future use"""
        self.dynamic_cache[field_name] = field_info
        
        #persist to disk
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, 'w') as f:
                json.dump(self.dynamic_cache, f, indent=2)
        except Exception as e:
            print(f"⚠️  Failed to persist cache: {e}")
    
    def get_validation_summary(self, field_names: List[str]) -> str:
        """get human-readable validation summary"""
        results = self.validate_fields(field_names)
        
        summary = []
        summary.append(f"Field Validation Summary:")
        summary.append(f"  ✓ Valid: {len(results['valid_fields'])}")
        summary.append(f"  ✗ Invalid: {len(results['invalid_fields'])}")
        summary.append(f"  ? Needs Research: {len(results['needs_research'])}")
        
        if results['invalid_fields']:
            summary.append(f"\nInvalid fields:")
            for field_info in results['invalid_fields']:
                summary.append(f"  - {field_info['field']}: {field_info['error']}")
        
        if results['needs_research']:
            summary.append(f"\nFields requiring research:")
            for field in results['needs_research']:
                summary.append(f"  - {field}")
        
        return '\n'.join(summary)

if __name__ == '__main__':
    #test
    validator = ECSFieldValidator()
    
    test_fields = [
        'event.category',
        'process.name',
        'process.command_line',
        'custom.weird.field',
        'network.protocol'
    ]
    
    print(validator.get_validation_summary(test_fields))
