#!/bin/bash
#validate-setup.sh - validate complete setup (GCP + GitHub + local)
#
#what this does:
# 1. checks GCP project and APIs
# 2. checks service account and key
# 3. checks local .env configuration
# 4. checks Python dependencies
# 5. checks GitHub secrets
# 6. checks CTI folder
#
#usage:
#   chmod +x scripts/validate-setup.sh
#   ./scripts/validate-setup.sh

echo "================================"
echo "Setup Validation"
echo "================================"
echo ""

ERRORS=0

#check gcloud CLI
echo "Checking gcloud CLI..."
if command -v gcloud &> /dev/null; then
    echo "  ✓ gcloud CLI installed"
else
    echo "  ✗ gcloud CLI not found"
    ERRORS=$((ERRORS+1))
fi

#check gh CLI
echo ""
echo "Checking gh CLI..."
if command -v gh &> /dev/null; then
    echo "  ✓ gh CLI installed"
else
    echo "  ✗ gh CLI not found"
    ERRORS=$((ERRORS+1))
fi

#check service account key
echo ""
echo "Checking service account key..."
KEY_FILE="$HOME/sigma-detection-sa-key.json"

if [ -f "$KEY_FILE" ]; then
    echo "  ✓ Key file exists: $KEY_FILE"

    #extract project ID
    PROJECT_ID=$(cat "$KEY_FILE" | grep -o '"project_id": "[^"]*' | cut -d'"' -f4)
    echo "  ✓ Project ID: $PROJECT_ID"
else
    echo "  ✗ Key file not found: $KEY_FILE"
    echo "    Run: ./scripts/setup-gcp.sh"
    ERRORS=$((ERRORS+1))
    PROJECT_ID=""
fi

#check GCP project (if we have project ID)
if [ -n "$PROJECT_ID" ]; then
    echo ""
    echo "Checking GCP project..."

    if gcloud projects describe "$PROJECT_ID" &> /dev/null; then
        echo "  ✓ Project exists: $PROJECT_ID"

        #check APIs
        echo "  Checking APIs..."
        APIS=("aiplatform.googleapis.com" "generativelanguage.googleapis.com")

        for API in "${APIS[@]}"; do
            if gcloud services list --enabled --project="$PROJECT_ID" --filter="name:$API" --format="value(name)" | grep -q "$API"; then
                echo "    ✓ $API enabled"
            else
                echo "    ✗ $API not enabled"
                ERRORS=$((ERRORS+1))
            fi
        done
    else
        echo "  ✗ Project not found: $PROJECT_ID"
        ERRORS=$((ERRORS+1))
    fi
fi

#check local .env file
echo ""
echo "Checking local .env configuration..."

if [ -f ".env" ]; then
    echo "  ✓ .env file exists"

    #check required vars
    if grep -q "GOOGLE_CLOUD_PROJECT=" .env; then
        ENV_PROJECT=$(grep "GOOGLE_CLOUD_PROJECT=" .env | cut -d'=' -f2)
        echo "  ✓ GOOGLE_CLOUD_PROJECT set: $ENV_PROJECT"
    else
        echo "  ✗ GOOGLE_CLOUD_PROJECT not set in .env"
        ERRORS=$((ERRORS+1))
    fi

    if grep -q "GOOGLE_APPLICATION_CREDENTIALS=" .env; then
        echo "  ✓ GOOGLE_APPLICATION_CREDENTIALS set"
    else
        echo "  ✗ GOOGLE_APPLICATION_CREDENTIALS not set in .env"
        ERRORS=$((ERRORS+1))
    fi
else
    echo "  ✗ .env file not found"
    echo "    Run: cp .env.example .env"
    ERRORS=$((ERRORS+1))
fi

#check Python venv
echo ""
echo "Checking Python environment..."

if [ -d "venv" ]; then
    echo "  ✓ Virtual environment exists"

    #check if dependencies installed
    if [ -f "venv/bin/python" ]; then
        PACKAGES=$(venv/bin/pip list 2>/dev/null | grep -E "(google-adk|pysigma|pydantic)" | wc -l)
        if [ "$PACKAGES" -gt 0 ]; then
            echo "  ✓ Dependencies installed ($PACKAGES key packages found)"
        else
            echo "  ✗ Dependencies not installed"
            echo "    Run: source venv/bin/activate && pip install -r requirements.txt"
            ERRORS=$((ERRORS+1))
        fi
    fi
else
    echo "  ✗ Virtual environment not found"
    echo "    Run: python3.11 -m venv venv"
    ERRORS=$((ERRORS+1))
fi

#check GitHub secrets (if gh available)
if command -v gh &> /dev/null; then
    echo ""
    echo "Checking GitHub secrets..."

    if gh auth status &> /dev/null; then
        SECRETS=$(gh secret list 2>/dev/null | grep -E "(GCP_SA_KEY|GCP_PROJECT_ID)" | wc -l)

        if [ "$SECRETS" -eq 2 ]; then
            echo "  ✓ GitHub secrets configured"
            gh secret list 2>/dev/null | grep -E "(GCP_SA_KEY|GCP_PROJECT_ID)" | while read line; do
                echo "    ✓ $line"
            done
        else
            echo "  ✗ GitHub secrets not configured ($SECRETS/2)"
            echo "    Run: ./scripts/setup-github-secrets.sh"
            ERRORS=$((ERRORS+1))
        fi
    else
        echo "  ⚠ Not authenticated to GitHub (skipping secrets check)"
    fi
fi

#check CTI folder
echo ""
echo "Checking CTI folder..."

if [ -d "sigma_detection_agent/cti_src" ]; then
    echo "  ✓ CTI folder exists"

    #count files
    CTI_FILES=$(find sigma_detection_agent/cti_src -type f \( -name "*.md" -o -name "*.txt" -o -name "*.pdf" -o -name "*.docx" \) | wc -l)
    echo "  ✓ CTI files: $CTI_FILES"

    if [ "$CTI_FILES" -eq 0 ]; then
        echo "    ⚠ No CTI files found (add files to test)"
    fi
else
    echo "  ✗ CTI folder not found"
    ERRORS=$((ERRORS+1))
fi

#check project structure
echo ""
echo "Checking project structure..."

DIRS=(
    "sigma_detection_agent/schemas"
    "sigma_detection_agent/tools"
    "sigma_detection_agent/prompts"
    "generated"
    "staged_rules"
    "production_rules"
    "scripts"
)

for DIR in "${DIRS[@]}"; do
    if [ -d "$DIR" ]; then
        echo "  ✓ $DIR/"
    else
        echo "  ✗ $DIR/ missing"
        ERRORS=$((ERRORS+1))
    fi
done

#summary
echo ""
echo "================================"

if [ $ERRORS -eq 0 ]; then
    echo "✓ All validation checks passed!"
    echo "================================"
    echo ""
    echo "System is ready!"
    echo ""
    echo "Next steps:"
    echo "  1. Test CTI loading:"
    echo "     source venv/bin/activate"
    echo "     python run_agent.py --test-cti"
    echo ""
    echo "  2. Add your CTI files:"
    echo "     cp your-threat-intel.pdf sigma_detection_agent/cti_src/"
    echo ""
    echo "  3. Run agent (Phase 2+):"
    echo "     python run_agent.py --interactive"
    exit 0
else
    echo "✗ Validation failed with $ERRORS error(s)"
    echo "================================"
    echo ""
    echo "Fix errors above and re-run:"
    echo "  ./scripts/validate-setup.sh"
    exit 1
fi
