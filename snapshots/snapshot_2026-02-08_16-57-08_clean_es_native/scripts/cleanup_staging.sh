#!/bin/bash
#cleanup staging folders and mixed JSON/YAML artifacts

echo "Cleaning staging artifacts..."

#remove temp staging folders
rm -rf generated/staging/
echo "✓ Removed generated/staging/"

#remove mixed JSON in detection_rules (keep only YAML)
if [ -d "generated/detection_rules" ]; then
    JSON_COUNT=$(find generated/detection_rules -name "*.json" 2>/dev/null | wc -l)
    if [ "$JSON_COUNT" -gt 0 ]; then
        find generated/detection_rules -name "*.json" -delete
        echo "✓ Removed $JSON_COUNT JSON files from detection_rules/"
    fi
fi

#remove old integration test results
rm -f integration_test_results.yml llm_judge_report.yml
echo "✓ Removed old test results"

echo "Cleanup complete"
