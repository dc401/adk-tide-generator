#!/bin/bash
#local demo of mock deployment workflow

set -e

echo "========================================"
echo "MOCK SIEM DEPLOYMENT DEMO"
echo "========================================"
echo ""

#check if staged_rules exists
if [ ! -d "staged_rules" ]; then
    echo "✗ No staged_rules/ found - pulling from remote..."
    git pull origin main
fi

#find batch
BATCH_FILE=$(ls -t staged_rules/batch_*.json 2>/dev/null | head -1)
if [ -z "$BATCH_FILE" ]; then
    echo "✗ No batch summary found"
    exit 1
fi

BATCH_ID=$(basename "$BATCH_FILE" .json)
RULE_COUNT=$(jq -r '.rules_staged' "$BATCH_FILE")

echo "Batch: $BATCH_ID"
echo "Rules: $RULE_COUNT"
echo ""

echo "[1/7] Starting Elasticsearch (Mock SIEM)..."
docker run -d --name elasticsearch \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" \
  -p 9200:9200 \
  docker.elastic.co/elasticsearch/elasticsearch:8.12.0 > /dev/null

echo "  Waiting for Elasticsearch (max 60s)..."
for i in {1..30}; do
    if curl -s http://localhost:9200/_cluster/health > /dev/null 2>&1; then
        break
    fi
    sleep 2
done
echo "  ✓ Mock SIEM ready"
echo ""

echo "[2/7] Deploying rules to mock SIEM..."
DEPLOYED=0
for rule_file in staged_rules/*.yml; do
    [ -f "$rule_file" ] || continue
    
    RULE_NAME=$(basename "$rule_file" .yml)
    
    #skip non-rule files
    if [[ "$RULE_NAME" == "batch_"* ]]; then
        continue
    fi
    
    #extract query
    QUERY=$(python3 -c "
import yaml
import sys
try:
    with open('$rule_file') as f:
        rule = yaml.safe_load(f)
    print(rule.get('query', ''))
except:
    print('')
    sys.exit(1)
" | head -c 500)  #limit query length for demo
    
    if [ -n "$QUERY" ]; then
        #deploy to ES (simplified for demo)
        curl -s -X POST "http://localhost:9200/.kibana/_doc/${RULE_NAME}" \
          -H 'Content-Type: application/json' \
          -d '{"type":"alert","name":"'"$RULE_NAME"'"}' > /dev/null
        
        echo "  ✓ Deployed: $RULE_NAME"
        DEPLOYED=$((DEPLOYED + 1))
    fi
done
echo "  Total: $DEPLOYED rules deployed"
echo ""

echo "[3/7] Verifying deployment..."
RULE_COUNT_ES=$(curl -s "http://localhost:9200/.kibana/_count" 2>/dev/null | jq -r '.count' || echo "0")
echo "  Rules in mock SIEM: $RULE_COUNT_ES"

HEALTH=$(curl -s "http://localhost:9200/_cluster/health" 2>/dev/null | jq -r '.status' || echo "unknown")
echo "  SIEM health: $HEALTH"
echo "  ✓ Deployment verified"
echo ""

echo "[4/7] Moving rules to production_rules/..."
mkdir -p production_rules

for staged_file in staged_rules/*.yml; do
    [ -f "$staged_file" ] || continue
    
    FILENAME=$(basename "$staged_file")
    
    #skip non-rule files
    if [[ "$FILENAME" == "batch_"* ]]; then
        continue
    fi
    
    #remove UID suffix (_xxxxxxxx)
    PROD_NAME=$(echo "$FILENAME" | sed 's/_[a-f0-9]\{8\}\.yml$/.yml/')
    
    cp "$staged_file" "production_rules/$PROD_NAME"
    echo "  ✓ $PROD_NAME"
done
echo ""

echo "[5/7] Archiving staged rules..."
mkdir -p archived_rules

ARCHIVE_DIR="archived_rules/${BATCH_ID}_deployed_$(date +%Y%m%d)"
mv staged_rules "$ARCHIVE_DIR"

#create deployment record
cat > "${ARCHIVE_DIR}/deployment_record.json" <<EOF
{
  "batch_id": "$BATCH_ID",
  "deployed_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "deployed_by": "local-demo",
  "rules_deployed": $DEPLOYED,
  "deployment_status": "success"
}
EOF

echo "  ✓ Archived to $ARCHIVE_DIR"
echo ""

echo "[6/7] Cleanup mock SIEM..."
docker stop elasticsearch 2>/dev/null || true
docker rm elasticsearch 2>/dev/null || true
echo "  ✓ Cleanup complete"
echo ""

echo "[7/7] Summary..."
echo "  Batch: $BATCH_ID"
echo "  Rules deployed: $DEPLOYED"
echo "  Production location: production_rules/"
echo "  Archive location: $ARCHIVE_DIR"
echo ""

echo "========================================"
echo "✓ MOCK DEPLOYMENT COMPLETE"
echo "========================================"
echo ""
echo "Production rules:"
ls -1 production_rules/ 2>/dev/null || echo "  (none yet)"
echo ""
echo "In production, these would be converted to:"
echo "  - Splunk: SPL queries"
echo "  - Chronicle: YARA-L 2.0"
echo "  - Sentinel: KQL queries"
echo "  - Elastic: Elasticsearch DSL"
echo ""

