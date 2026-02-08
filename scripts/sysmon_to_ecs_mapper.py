#!/usr/bin/env python3
"""
Sysmon to ECS Field Mapper

Converts Sysmon Windows Event fields to Elastic Common Schema (ECS) fields
for compatibility with Sigma rules that expect ECS format.
"""

SYSMON_TO_ECS_MAPPING = {
    #process fields
    'Image': 'process.executable',
    'CommandLine': 'process.command_line',
    'ParentImage': 'process.parent.executable',
    'ParentCommandLine': 'process.parent.command_line',
    'ProcessId': 'process.pid',
    'ProcessGuid': 'process.entity_id',
    'User': 'user.name',

    #file fields
    'TargetFilename': 'file.path',
    'TargetObject': 'registry.path',

    #event fields
    'EventID': 'event.code',
    'UtcTime': '@timestamp',

    #network fields
    'DestinationIp': 'destination.ip',
    'DestinationPort': 'destination.port',
    'SourceIp': 'source.ip',
    'SourcePort': 'source.port',
}

def convert_sysmon_to_ecs(sysmon_doc: dict) -> dict:
    """Convert Sysmon field names to ECS format"""
    ecs_doc = {}

    for sysmon_field, value in sysmon_doc.items():
        if sysmon_field in SYSMON_TO_ECS_MAPPING:
            ecs_field = SYSMON_TO_ECS_MAPPING[sysmon_field]

            #handle nested ECS fields (e.g., process.executable)
            if '.' in ecs_field:
                parts = ecs_field.split('.')
                current = ecs_doc
                for part in parts[:-1]:
                    if part not in current:
                        current[part] = {}
                    current = current[part]
                current[parts[-1]] = value
            else:
                ecs_doc[ecs_field] = value
        else:
            #keep unmapped fields as-is
            ecs_doc[sysmon_field] = value

    return ecs_doc

if __name__ == '__main__':
    import json
    import sys
    from pathlib import Path

    if len(sys.argv) != 2:
        print("Usage: python sysmon_to_ecs_mapper.py <test_payload.json>")
        sys.exit(1)

    payload_path = Path(sys.argv[1])

    with open(payload_path) as f:
        payload = json.load(f)

    #convert log_entry if present
    if 'log_entry' in payload:
        payload['log_entry'] = convert_sysmon_to_ecs(payload['log_entry'])
    else:
        payload = convert_sysmon_to_ecs(payload)

    print(json.dumps(payload, indent=2))
