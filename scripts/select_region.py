#!/usr/bin/env python3
"""select GCP region using round-robin rotation based on timestamp

rotates through multiple regions to distribute API quota usage
uses current hour of day for deterministic selection (no state needed)
"""
import sys
from datetime import datetime

#available Gemini API regions (all support Vertex AI)
REGIONS = [
    'us-central1',
    'global',
    'us-south1',
    'us-east5',
    'us-west1',
    'us-east1',
    'us-east4',
    'us-west4',
]

def select_region():
    """select region based on current hour (rotates every hour)"""
    current_hour = datetime.utcnow().hour
    region_index = current_hour % len(REGIONS)
    selected_region = REGIONS[region_index]
    
    print(f"Region rotation: Hour {current_hour} UTC → {selected_region}", file=sys.stderr)
    print(f"Available regions: {', '.join(REGIONS)}", file=sys.stderr)
    print(selected_region)  #stdout for GitHub Actions capture
    
    return selected_region

if __name__ == '__main__':
    select_region()
