#!/usr/bin/env python3
"""ECS field research agent - uses ADK reflection to research unknown fields"""
import json
import asyncio
from google import genai
from google.genai import types
from typing import Dict

async def research_ecs_field(field_name: str, client: genai.Client) -> Dict:
    """research unknown ECS field using reflection agent"""
    
    prompt = f"""You are an Elastic Common Schema (ECS) expert. Research the field: {field_name}

Your task:
1. Search Elastic ECS documentation to determine if this is a valid field
2. If valid, extract: data type, description, which events use it, example values
3. If invalid, explain why and suggest correct alternatives

Return ONLY valid JSON (no markdown, no code blocks):
{{
    "valid": true or false,
    "field": "{field_name}",
    "type": "keyword|text|long|ip|date|...",
    "description": "brief description",
    "example": "example value",
    "common_in": ["event types that commonly have this field"],
    "source": "URL where documented",
    "confidence": "high|medium|low",
    "alternatives": ["suggested correct fields if invalid"]
}}

If you cannot find definitive information, set confidence to "low" and valid to false.
"""
    
    try:
        #use Gemini 2.5 Flash with reflection
        response = await client.aio.models.generate_content(
            model='gemini-2.0-flash-exp',  #will update to 2.5 when available
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.0,  #deterministic for schema research
                response_modalities=['TEXT'],
                thinking_config=types.ThinkingConfig(
                    mode=types.ThinkingMode.THINKING
                )
            )
        )
        
        response_text = response.text
        
        #extract JSON from response (handle markdown code blocks)
        if '```json' in response_text:
            json_start = response_text.find('```json') + 7
            json_end = response_text.find('```', json_start)
            response_text = response_text[json_start:json_end].strip()
        elif '```' in response_text:
            json_start = response_text.find('```') + 3
            json_end = response_text.find('```', json_start)
            response_text = response_text[json_start:json_end].strip()
        
        result = json.loads(response_text)
        
        #validate result structure
        required_fields = ['valid', 'field', 'confidence']
        if not all(f in result for f in required_fields):
            return {
                'valid': False,
                'field': field_name,
                'error': 'Research agent returned incomplete result',
                'confidence': 'low'
            }
        
        print(f"  ✓ Researched {field_name}: valid={result['valid']}, confidence={result.get('confidence')}")
        return result
        
    except json.JSONDecodeError as e:
        print(f"  ✗ Research agent returned invalid JSON: {e}")
        print(f"  Response: {response_text[:200]}...")
        return {
            'valid': False,
            'field': field_name,
            'error': f'Research failed - invalid JSON: {e}',
            'confidence': 'low'
        }
        
    except Exception as e:
        print(f"  ✗ Research failed for {field_name}: {e}")
        return {
            'valid': False,
            'field': field_name,
            'error': f'Research failed: {e}',
            'confidence': 'low'
        }

async def research_multiple_fields(field_names: list, client: genai.Client, max_concurrent: int = 3) -> Dict[str, Dict]:
    """research multiple fields concurrently"""
    
    print(f"\nResearching {len(field_names)} unknown fields...")
    
    results = {}
    
    #batch research to avoid rate limits
    for i in range(0, len(field_names), max_concurrent):
        batch = field_names[i:i + max_concurrent]
        
        #research batch concurrently
        tasks = [research_ecs_field(field, client) for field in batch]
        batch_results = await asyncio.gather(*tasks)
        
        #store results
        for field, result in zip(batch, batch_results):
            results[field] = result
        
        #small delay between batches
        if i + max_concurrent < len(field_names):
            await asyncio.sleep(2.0)
    
    #summary
    valid_count = sum(1 for r in results.values() if r.get('valid'))
    print(f"✓ Research complete: {valid_count}/{len(field_names)} fields validated")
    
    return results

if __name__ == '__main__':
    #test
    async def test():
        client = genai.Client(
            vertexai=True,
            project='your-project',
            location='us-central1'
        )
        
        test_fields = [
            'event.category',  #should be valid
            'custom.weird.field',  #should be invalid
            'threat.indicator.type'  #should be valid
        ]
        
        results = await research_multiple_fields(test_fields, client)
        
        for field, result in results.items():
            print(f"\n{field}:")
            print(f"  Valid: {result.get('valid')}")
            print(f"  Confidence: {result.get('confidence')}")
            if result.get('valid'):
                print(f"  Type: {result.get('type')}")
                print(f"  Description: {result.get('description')}")
    
    #asyncio.run(test())
    print("Research agent ready (test commented out - requires GCP auth)")
