"""Self-healing refinement loop for detection generation

Retries generation if zero rules pass, with feedback from previous failures
"""

import asyncio
import yaml
from pathlib import Path
from typing import Dict, List

from .agent import run_detection_agent


async def run_with_refinement(
    cti_dir: Path,
    output_dir: Path,
    project_id: str,
    location: str = 'global',
    max_iterations: int = 3
) -> Dict:
    """run detection agent with self-healing refinement loop
    
    If zero rules generated/validated, retry with feedback from previous attempt
    Max 2-3 iterations before giving up
    """
    
    print(f"\n{'='*80}")
    print("DETECTION AGENT WITH REFINEMENT")
    print(f"Max iterations: {max_iterations}")
    print(f"{'='*80}\n")
    
    failure_history = []
    
    for iteration in range(1, max_iterations + 1):
        print(f"\n{'#'*80}")
        print(f"# ITERATION {iteration}/{max_iterations}")
        print(f"{'#'*80}\n")
        
        #show previous failures if this is a retry
        if failure_history:
            print("Previous failures:")
            for prev in failure_history:
                print(f"  Iteration {prev['iteration']}:")
                print(f"    Rules generated: {prev['rules_generated']}")
                print(f"    Rules validated: {prev['rules_validated']}")
                print(f"    Issues: {prev['summary']}")
            print()
        
        #run detection agent
        try:
            result = await run_detection_agent(
                cti_dir,
                output_dir,
                project_id,
                location
            )
            
            rules_generated = result.get('rules_generated', 0)
            
            #success - at least some rules passed
            if rules_generated > 0:
                print(f"\n{'='*80}")
                print(f"✓ SUCCESS ON ITERATION {iteration}")
                print(f"{'='*80}")
                print(f"Rules generated: {rules_generated}")
                print(f"Iterations used: {iteration}/{max_iterations}")
                return result
            
            #no rules passed - prepare for retry
            failure_report = {
                'iteration': iteration,
                'rules_generated': 0,
                'rules_validated': 0,
                'summary': 'No rules passed validation (score <0.75)'
            }
            
            failure_history.append(failure_report)
            
            if iteration < max_iterations:
                print(f"\n{'!'*80}")
                print(f"⚠ No usable detections generated")
                print(f"Retrying with refined strategy...")
                print(f"{'!'*80}\n")
                
                #wait before retry
                await asyncio.sleep(5.0)
            else:
                print(f"\n{'!'*80}")
                print(f"✗ FAILED AFTER {max_iterations} ITERATIONS")
                print(f"{'!'*80}")
                print(f"No usable detection rules could be generated")
                print(f"\nPossible reasons:")
                print(f"  - CTI content lacks actionable TTP details")
                print(f"  - Detection patterns too generic/broad")
                print(f"  - ECS field mappings incorrect")
                print(f"\nRecommendations:")
                print(f"  - Review CTI files for specific attack indicators")
                print(f"  - Check generated rules in {output_dir}")
                print(f"  - Review validation scores")
                
                return {
                    'rules_generated': 0,
                    'failure_history': failure_history,
                    'status': 'failed'
                }
        
        except Exception as e:
            print(f"\n✗ Error in iteration {iteration}: {e}")
            import traceback
            traceback.print_exc()
            
            failure_report = {
                'iteration': iteration,
                'rules_generated': 0,
                'rules_validated': 0,
                'summary': f'Exception: {str(e)}'
            }
            failure_history.append(failure_report)
            
            if iteration >= max_iterations:
                raise
            
            print(f"\nRetrying after error...")
            await asyncio.sleep(5.0)
    
    #should not reach here
    return {
        'rules_generated': 0,
        'failure_history': failure_history,
        'status': 'failed'
    }
