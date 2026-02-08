"""Elasticsearch-native Detection Agent

Generates detection rules directly from CTI without Sigma intermediate format.
"""

import asyncio
import json
import os
import random
import sys
import yaml
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

from google import genai
from google.genai import types
from google.api_core.exceptions import ResourceExhausted

#import schemas
from .schemas import (
    DetectionRule,
    DetectionRuleOutput,
    ValidationResult,
    EvaluationResult,
    SecurityScanResult,
)
from .tools import load_cti_files

#retry configurations (from gcphunter pattern)
AGGRESSIVE_RETRY_CONFIG = types.HttpOptions(
    retry_options=types.HttpRetryOptions(
        initial_delay=15,
        attempts=6,
        exp_base=6,
        max_delay=92,
        http_status_codes=[429, 500, 503, 504]
    )
)

FLASH_RETRY_CONFIG = types.HttpOptions(
    retry_options=types.HttpRetryOptions(
        initial_delay=8,
        attempts=4,
        exp_base=3,
        max_delay=72,
        http_status_codes=[429, 500, 503, 504]
    )
)

#inter-agent throttling
INTER_AGENT_DELAY = 3.0

#model configurations
MODELS = {
    'flash': {
        'name': 'gemini-2.5-flash',
        'retry_config': FLASH_RETRY_CONFIG,
        'default_temp': 0.3,
    },
    'pro': {
        'name': 'gemini-2.5-pro',
        'retry_config': AGGRESSIVE_RETRY_CONFIG,
        'default_temp': 0.2,
    }
}


def safe_json_parse(text: str) -> Dict:
    """safely parse JSON from LLM output"""
    try:
        #try direct parse
        return json.loads(text)
    except json.JSONDecodeError:
        #extract from markdown code block
        if '```json' in text:
            start = text.find('```json') + 7
            end = text.find('```', start)
            json_text = text[start:end].strip()
            return json.loads(json_text)
        elif '```' in text:
            start = text.find('```') + 3
            end = text.find('```', start)
            json_text = text[start:end].strip()
            return json.loads(json_text)
        raise


async def generate_with_retry(client, model_config: Dict, prompt: str,
                              system_instruction: str = None,
                              tools: list = None,
                              temperature: float = None,
                              max_retries: int = 3) -> str:
    """generate content with exponential backoff retry"""

    model_name = model_config['name']
    retry_config = model_config['retry_config']
    temp = temperature if temperature is not None else model_config['default_temp']

    #cant use controlled generation (JSON mode) with Google Search tool
    config_params = {
        'temperature': temp,
        'system_instruction': system_instruction
    }

    if not tools:
        config_params['response_mime_type'] = 'application/json'

    config = types.GenerateContentConfig(**config_params)

    if tools:
        config.tools = tools
    
    for attempt in range(max_retries):
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=prompt,
                config=config
            )
            return response.text
            
        except ResourceExhausted as e:
            if attempt == max_retries - 1:
                raise
            delay = min(20.0 * (2 ** attempt), 120.0)
            jitter = random.uniform(0, delay * 0.1)
            print(f"  Rate limited. Retrying in {delay + jitter:.1f}s...")
            await asyncio.sleep(delay + jitter)
            
        except Exception as e:
            print(f"  Error: {e}")
            if attempt == max_retries - 1:
                raise
            await asyncio.sleep(5.0)
    
    raise Exception("Max retries exceeded")


async def run_detection_agent(cti_dir: Path, output_dir: Path, project_id: str, location: str = 'global'):
    """main detection agent workflow"""
    
    print(f"\n{'='*80}")
    print("ELASTICSEARCH DETECTION AGENT")
    print(f"{'='*80}\n")
    
    #setup Vertex AI
    os.environ['GOOGLE_GENAI_USE_VERTEXAI'] = 'true'
    client = genai.Client(
        vertexai=True,
        project=project_id,
        location=location
    )
    
    #load prompts
    prompts_dir = Path(__file__).parent / 'prompts'
    with open(prompts_dir / 'security_guard.md') as f:
        security_prompt = f.read()
    with open(prompts_dir / 'detection_generator.md') as f:
        generator_prompt = f.read()
    with open(prompts_dir / 'validator.md') as f:
        validator_prompt = f.read()
    
    #step 1: load CTI files
    print("[1/5] Loading CTI files...")
    cti_result = load_cti_files(str(cti_dir))
    cti_content = cti_result['text_content']
    print(f"  ✓ Loaded {cti_result['files_loaded']} CTI files")
    
    #step 2: security scan
    print("\n[2/5] Security scan (OWASP LLM protection)...")
    security_scan_prompt = f"{security_prompt}\n\n## CTI Content to Analyze:\n\n{cti_content}"
    
    security_response = await generate_with_retry(
        client,
        MODELS['flash'],
        security_scan_prompt,
        temperature=0.3
    )
    
    security_result = SecurityScanResult(**safe_json_parse(security_response))
    print(f"  Risk Level: {security_result.risk_level}")
    print(f"  Action: {security_result.action}")
    
    if security_result.action == 'BLOCK':
        print(f"\n  🛑 BLOCKED: {security_result.recommendation}")
        print(f"  Analysis: {security_result.analysis}")
        sys.exit(1)
    
    if security_result.action == 'FLAG':
        print(f"  ⚠️  FLAGGED: {security_result.recommendation}")
    
    #step 3: generate detection rules
    print("\n[3/5] Generating detection rules...")
    generation_prompt = f"{generator_prompt}\n\n## CTI Intelligence:\n\n{cti_content}"
    
    await asyncio.sleep(INTER_AGENT_DELAY)
    
    gen_response = await generate_with_retry(
        client,
        MODELS['flash'],
        generation_prompt,
        temperature=0.3,
        tools=[types.Tool(google_search=types.GoogleSearch())]
    )
    
    rule_output = DetectionRuleOutput(**safe_json_parse(gen_response))
    print(f"  ✓ Generated {rule_output.total_rules} detection rules")
    
    #step 4: validate rules
    print("\n[4/5] Validating detection rules...")
    validated_rules = []
    
    for rule in rule_output.rules:
        print(f"\n  Validating: {rule.name}")
        
        #check test case requirements
        test_validation = rule.validate_test_cases()
        if not test_validation['valid']:
            print(f"    ✗ Test validation failed: {test_validation['errors']}")
            continue
        
        validation_prompt = f"{validator_prompt}\n\n## Detection Rule:\n\n{rule.model_dump_json(indent=2)}"
        
        await asyncio.sleep(INTER_AGENT_DELAY)
        
        val_response = await generate_with_retry(
            client,
            MODELS['pro'],
            validation_prompt,
            temperature=0.2,
            tools=[types.Tool(google_search=types.GoogleSearch())]
        )
        
        validation = ValidationResult(**safe_json_parse(val_response))
        print(f"    Overall Score: {validation.overall_score:.2f}")
        
        if validation.overall_score >= 0.75:
            print(f"    ✓ APPROVED")
            validated_rules.append(rule)
        else:
            print(f"    ✗ REJECTED: {validation.recommendation}")
            for issue in validation.issues:
                print(f"      - {issue}")
    
    print(f"\n  ✓ Validated {len(validated_rules)}/{rule_output.total_rules} rules")
    
    #step 5: save output
    print("\n[5/5] Saving detection rules...")
    output_dir.mkdir(parents=True, exist_ok=True)
    rules_dir = output_dir / 'detection_rules'
    rules_dir.mkdir(parents=True, exist_ok=True)

    for rule in validated_rules:
        #sanitize filename: remove invalid chars
        safe_name = rule.name.lower().replace(' ', '_').replace('/', '_').replace('\\', '_')
        rule_file = rules_dir / f"{safe_name}.yml"
        with open(rule_file, 'w') as f:
            yaml.dump(rule.model_dump(), f, default_flow_style=False, sort_keys=False)
        print(f"  ✓ Saved: {rule_file.name}")

    #save CTI context
    context_file = output_dir / 'cti_context.yml'
    with open(context_file, 'w') as f:
        yaml.dump(rule_output.cti_context, f, default_flow_style=False, sort_keys=False)
    
    print(f"\n{'='*80}")
    print(f"GENERATION COMPLETE")
    print(f"{'='*80}\n")
    print(f"Rules generated: {len(validated_rules)}")
    print(f"Output directory: {output_dir}")
    print(f"\nNext: Run integration tests with scripts/integration_test_ci.py")
    
    return {
        'rules_generated': len(validated_rules),
        'cti_context': rule_output.cti_context
    }


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate Elasticsearch Detection Rules from CTI')
    parser.add_argument('--cti-dir', default='cti_src', help='CTI files directory')
    parser.add_argument('--output-dir', default='generated/detection_rules', help='Output directory')
    parser.add_argument('--project', help='GCP project ID (or use GOOGLE_CLOUD_PROJECT env)')
    parser.add_argument('--location', default='global', help='GCP region')
    
    args = parser.parse_args()
    
    project_id = args.project or os.environ.get('GOOGLE_CLOUD_PROJECT')
    if not project_id:
        print("ERROR: GCP project ID required (--project or GOOGLE_CLOUD_PROJECT env)")
        sys.exit(1)
    
    asyncio.run(run_detection_agent(
        Path(args.cti_dir),
        Path(args.output_dir),
        project_id,
        args.location
    ))
