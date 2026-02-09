#!/usr/bin/env python3
"""Iterative validation for detection rules with field and syntax checking"""
import asyncio
import json
from typing import Dict, List
from datetime import datetime

from detection_agent.tools.validate_lucene import validate_lucene_query, extract_fields_from_query
from detection_agent.tools.validate_ecs_fields import ECSFieldValidator
from detection_agent.tools.research_ecs_field import research_multiple_fields

async def validate_and_refine_rules(
    rules_data: Dict,
    client,
    model_config: Dict,
    generator_prompt: str,
    cti_content: str,
    generate_with_retry_func,
    max_iterations: int = 3,
    inter_agent_delay: float = 3.0
) -> Dict:
    """iteratively validate and refine detection rules"""
    
    print(f"\n{'='*80}")
    print("ITERATIVE VALIDATION & REFINEMENT")
    print(f"{'='*80}")
    
    field_validator = ECSFieldValidator()
    iteration_history = []
    
    for iteration in range(max_iterations):
        print(f"\n[Iteration {iteration + 1}/{max_iterations}]")
        print(f"{'-'*80}")
        
        validation_issues = []
        all_valid = True
        
        #validate each rule
        for rule_idx, rule in enumerate(rules_data.get('rules', [])):
            rule_name = rule.get('name', f'rule_{rule_idx}')
            query = rule.get('query', '')
            
            print(f"\n  Validating rule {rule_idx + 1}: {rule_name}")
            
            #1. validate Lucene syntax
            print(f"    [1/2] Lucene syntax check...")
            lucene_result = validate_lucene_query(query)
            
            if not lucene_result['valid']:
                all_valid = False
                error_msg = f"Rule '{rule_name}': Lucene syntax error - {lucene_result.get('error_detail', lucene_result.get('error'))}"
                validation_issues.append(error_msg)
                print(f"      ✗ {lucene_result.get('error')}")
                continue  #skip field validation if syntax invalid
            else:
                print(f"      ✓ Valid Lucene syntax")
            
            #2. extract and validate fields
            print(f"    [2/2] ECS field validation...")
            fields = extract_fields_from_query(query)
            print(f"      Found {len(fields)} fields: {', '.join(fields)}")
            
            field_results = field_validator.validate_fields(fields)
            
            #show valid fields
            if field_results['valid_fields']:
                print(f"      ✓ {len(field_results['valid_fields'])} valid fields")
            
            #handle fields needing research
            if field_results['needs_research']:
                print(f"      ? {len(field_results['needs_research'])} fields need research:")
                for field in field_results['needs_research']:
                    print(f"        - {field}")
                
                #research unknown fields
                print(f"      Researching unknown fields...")
                research_results = await research_multiple_fields(
                    field_results['needs_research'],
                    client,
                    max_concurrent=2
                )
                
                #cache researched fields
                for field, research in research_results.items():
                    if research.get('valid') and research.get('confidence') in ['high', 'medium']:
                        field_validator.cache_field(field, research)
                        print(f"        ✓ {field}: valid ({research.get('type')})")
                    else:
                        all_valid = False
                        error_msg = f"Rule '{rule_name}': Invalid field '{field}' - {research.get('error', 'not found in ECS')}"
                        validation_issues.append(error_msg)
                        print(f"        ✗ {field}: {research.get('error', 'invalid')}")
                        
                        #suggest alternatives if available
                        if research.get('alternatives'):
                            print(f"          Suggested alternatives: {', '.join(research['alternatives'])}")
            
            #handle invalid fields
            if field_results['invalid_fields']:
                all_valid = False
                for invalid in field_results['invalid_fields']:
                    error_msg = f"Rule '{rule_name}': {invalid['error']}"
                    validation_issues.append(error_msg)
                    print(f"      ✗ {invalid['field']}: {invalid['error']}")
        
        #store iteration result
        iteration_history.append({
            'iteration': iteration + 1,
            'all_valid': all_valid,
            'issues_count': len(validation_issues),
            'timestamp': datetime.now().isoformat()
        })
        
        #check if all valid
        if all_valid:
            print(f"\n{'='*80}")
            print(f"✓ ALL RULES VALID after {iteration + 1} iteration(s)")
            print(f"{'='*80}")
            return {
                'rules': rules_data.get('rules', []),
                'cti_context': rules_data.get('cti_context', {}),
                'total_rules': len(rules_data.get('rules', [])),
                'validation_iterations': iteration + 1,
                'validation_history': iteration_history
            }
        
        #not valid - check if we can refine
        if iteration < max_iterations - 1:
            print(f"\n  ⚠️  {len(validation_issues)} validation issues found")
            print(f"  Refining rules with feedback...")
            
            #build refinement prompt
            refinement_feedback = "\n".join([f"- {issue}" for issue in validation_issues[:10]])  #limit to top 10
            
            refinement_prompt = f"""{generator_prompt}

## CTI Intelligence:

{cti_content}

## VALIDATION FEEDBACK FROM ITERATION {iteration + 1}:

The previous generation had the following issues that MUST be fixed:

{refinement_feedback}

CRITICAL FIXES REQUIRED:
1. Use ONLY valid ECS field names (check Elastic Common Schema documentation)
2. Ensure Lucene query syntax is correct (no literal slashes, balanced parentheses)
3. Use wildcards (*) around command-line flags instead of literal special characters
4. Test that all fields actually exist in ECS before using them

Generate corrected rules that fix these specific issues.
"""
            
            #regenerate with feedback
            print(f"\n  Regenerating rules with fixes...")
            await asyncio.sleep(inter_agent_delay)
            
            refined_response = await generate_with_retry_func(
                client,
                model_config,
                refinement_prompt,
                temperature=0.2,  #lower temp for correction
                tools=[{'type': 'google_search'}],
                timeout=300  # 5min - validation + field research + JSON regeneration (up to 3 iterations)
            )
            
            #parse refined response
            try:
                from detection_agent.agent import safe_json_parse
                rules_data = safe_json_parse(refined_response)
                
                #ensure required fields exist
                if 'rules' not in rules_data:
                    print(f"  ✗ Refined response missing 'rules' field")
                    break
                
                if 'cti_context' not in rules_data:
                    rules_data['cti_context'] = {
                        'source': 'cti_src',
                        'analyzed': datetime.now().isoformat()
                    }
                
                print(f"  ✓ Regenerated {len(rules_data.get('rules', []))} rules")
                
            except Exception as e:
                print(f"  ✗ Failed to parse refined response: {e}")
                break
        else:
            #max iterations reached
            print(f"\n{'='*80}")
            print(f"⚠️  MAX ITERATIONS REACHED ({max_iterations})")
            print(f"{'='*80}")
            print(f"\nRemaining issues:")
            for issue in validation_issues[:10]:
                print(f"  - {issue}")
            
            if len(validation_issues) > 10:
                print(f"  ... and {len(validation_issues) - 10} more")
            
            #return best attempt
            return {
                'rules': rules_data.get('rules', []),
                'cti_context': rules_data.get('cti_context', {}),
                'total_rules': len(rules_data.get('rules', [])),
                'validation_iterations': max_iterations,
                'validation_history': iteration_history,
                'validation_incomplete': True,
                'remaining_issues': validation_issues
            }
    
    #shouldn't reach here
    return rules_data
