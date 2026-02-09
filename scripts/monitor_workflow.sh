#!/bin/bash
# Monitor workflow run with 5-minute interval checks

RUN_ID=$1
CHECK_INTERVAL=300  # 5 minutes

if [ -z "$RUN_ID" ]; then
  echo "Usage: $0 <run_id>"
  exit 1
fi

echo "Monitoring workflow run: $RUN_ID"
echo "Check interval: $CHECK_INTERVAL seconds (5 minutes)"
echo ""

while true; do
  # Get current status
  STATUS=$(gh run view $RUN_ID --json status,conclusion --jq '{status: .status, conclusion: .conclusion}')

  CURRENT_STATUS=$(echo $STATUS | jq -r '.status')
  CONCLUSION=$(echo $STATUS | jq -r '.conclusion')

  TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

  echo "[$TIMESTAMP] Status: $CURRENT_STATUS"

  # If completed, show conclusion and exit
  if [ "$CURRENT_STATUS" == "completed" ]; then
    echo ""
    echo "=========================================="
    echo "WORKFLOW COMPLETED"
    echo "=========================================="
    echo "Conclusion: $CONCLUSION"
    echo ""

    # Show job summaries
    gh run view $RUN_ID --json jobs --jq '.jobs[] | "\(.name): \(.conclusion)"'

    echo ""
    echo "View full details:"
    echo "  gh run view $RUN_ID"
    echo "  gh run view $RUN_ID --log"

    exit 0
  fi

  # Show current jobs status
  echo "  Jobs:"
  gh run view $RUN_ID --json jobs --jq '.jobs[] | "    \(.name): \(.status)"' 2>/dev/null || echo "    (loading...)"

  echo ""
  echo "Next check in $CHECK_INTERVAL seconds..."
  sleep $CHECK_INTERVAL
done
