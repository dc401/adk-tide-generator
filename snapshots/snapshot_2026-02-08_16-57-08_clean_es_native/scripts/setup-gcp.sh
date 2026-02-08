#!/bin/bash
#setup-gcp.sh - automated GCP setup for sigma detection agent
#
#what this does:
# 1. creates GCP project (or uses existing)
# 2. enables required APIs
# 3. creates service account
# 4. grants least-privilege permissions
# 5. downloads service account key
#
#usage:
#   chmod +x scripts/setup-gcp.sh
#   ./scripts/setup-gcp.sh

set -e  #exit on error

echo "================================"
echo "GCP Setup for Sigma Detection Agent"
echo "================================"
echo ""

#check prerequisites
if ! command -v gcloud &> /dev/null; then
    echo "ERROR: gcloud CLI not found"
    echo "Install from: https://cloud.google.com/sdk/docs/install"
    exit 1
fi

echo "✓ gcloud CLI found"

#authenticate
echo ""
echo "Checking GCP authentication..."
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" &> /dev/null; then
    echo "Not authenticated. Running gcloud auth login..."
    gcloud auth login
fi

ACTIVE_ACCOUNT=$(gcloud auth list --filter=status:ACTIVE --format="value(account)")
echo "✓ Authenticated as: $ACTIVE_ACCOUNT"

#prompt for project ID (interactive with suggestions)
echo ""
echo "GCP Project Setup"
echo "-----------------"
echo "Choose an option:"
echo "  1. Create new project (auto-generate ID)"
echo "  2. Create new project (specify ID)"
echo "  3. Use existing project"
echo ""
read -p "Enter choice (1-3): " PROJECT_CHOICE

case $PROJECT_CHOICE in
    1)
        #auto-generate
        RANDOM_SUFFIX=$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 6 | head -n 1)
        PROJECT_ID="sigma-detection-$RANDOM_SUFFIX"
        echo "Generated project ID: $PROJECT_ID"
        ;;
    2)
        #user specifies
        read -p "Enter project ID: " PROJECT_ID

        #validate format
        if [[ ! "$PROJECT_ID" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]]; then
            echo "⚠ Warning: Project ID should be 6-30 chars, lowercase, numbers, hyphens"
            read -p "Continue anyway? (y/n): " CONTINUE
            if [ "$CONTINUE" != "y" ]; then
                exit 0
            fi
        fi
        ;;
    3)
        #use existing
        read -p "Enter existing project ID: " PROJECT_ID
        ;;
    *)
        echo "Invalid choice. Exiting..."
        exit 1
        ;;
esac

echo "Project ID: $PROJECT_ID"

#check if project exists
if gcloud projects describe "$PROJECT_ID" &> /dev/null; then
    echo "✓ Project exists: $PROJECT_ID"
    read -p "Use existing project? (y/n): " USE_EXISTING
    if [ "$USE_EXISTING" != "y" ]; then
        echo "Exiting..."
        exit 0
    fi
else
    #create project
    echo "Creating project: $PROJECT_ID..."
    gcloud projects create "$PROJECT_ID" --name="Sigma Detection Agent"
    echo "✓ Created project: $PROJECT_ID"
fi

#set active project
gcloud config set project "$PROJECT_ID"
echo "✓ Set active project: $PROJECT_ID"

#check billing (skip if command fails - user will see error when enabling APIs)
echo ""
echo "Checking billing..."
echo "⚠ Note: Billing must be enabled for Vertex AI to work"
echo "Enable at: https://console.cloud.google.com/billing/linkedaccount?project=$PROJECT_ID"
echo ""
read -p "Is billing enabled for this project? (y/n): " BILLING_CONFIRMED

if [ "$BILLING_CONFIRMED" != "y" ]; then
    echo "Please enable billing first, then re-run this script"
    exit 0
fi

#enable required APIs
echo ""
echo "Enabling required APIs..."

APIS=(
    "aiplatform.googleapis.com"
    "iam.googleapis.com"
)

for API in "${APIS[@]}"; do
    echo "  Enabling $API..."
    gcloud services enable "$API" --project="$PROJECT_ID"
done

echo "✓ APIs enabled"

#create service account
SA_NAME="sigma-detection-agent"
SA_EMAIL="$SA_NAME@$PROJECT_ID.iam.gserviceaccount.com"

echo ""
echo "Creating service account..."

if gcloud iam service-accounts describe "$SA_EMAIL" &> /dev/null; then
    echo "✓ Service account exists: $SA_EMAIL"
else
    gcloud iam service-accounts create "$SA_NAME" \
        --display-name="Sigma Detection Agent" \
        --description="Service account for automated detection engineering" \
        --project="$PROJECT_ID"
    echo "✓ Created service account: $SA_EMAIL"
fi

#grant permissions (least privilege)
echo ""
echo "Granting permissions..."

#only need aiplatform.user for Vertex AI (we use GOOGLE_GENAI_USE_VERTEXAI=true)
ROLES=(
    "roles/aiplatform.user"
)

for ROLE in "${ROLES[@]}"; do
    echo "  Granting $ROLE..."
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:$SA_EMAIL" \
        --role="$ROLE" \
        --condition=None \
        > /dev/null
done

echo "✓ Permissions granted"

#create and download service account key
echo ""
echo "Creating service account key..."

#ask for key file location
DEFAULT_KEY_FILE="$HOME/sigma-detection-sa-key.json"
echo "Default location: $DEFAULT_KEY_FILE"
read -p "Use default location? (y/n): " USE_DEFAULT_LOC

if [ "$USE_DEFAULT_LOC" = "y" ]; then
    KEY_FILE="$DEFAULT_KEY_FILE"
else
    read -p "Enter full path for key file: " KEY_FILE
fi

#expand ~ if present
KEY_FILE="${KEY_FILE/#\~/$HOME}"

#check if exists
if [ -f "$KEY_FILE" ]; then
    echo "⚠ Key file already exists: $KEY_FILE"
    read -p "Overwrite? (y/n): " OVERWRITE
    if [ "$OVERWRITE" != "y" ]; then
        echo "Skipping key creation (using existing key)..."
    else
        gcloud iam service-accounts keys create "$KEY_FILE" \
            --iam-account="$SA_EMAIL" \
            --project="$PROJECT_ID"
        chmod 600 "$KEY_FILE"
        echo "✓ Created key: $KEY_FILE"
    fi
else
    #create parent directory if needed
    KEY_DIR=$(dirname "$KEY_FILE")
    mkdir -p "$KEY_DIR"

    gcloud iam service-accounts keys create "$KEY_FILE" \
        --iam-account="$SA_EMAIL" \
        --project="$PROJECT_ID"
    chmod 600 "$KEY_FILE"
    echo "✓ Created key: $KEY_FILE"
fi

#validate setup
echo ""
echo "Validating setup..."

#check required API
API="aiplatform.googleapis.com"
if gcloud services list --enabled --project="$PROJECT_ID" --filter="name:$API" --format="value(name)" | grep -q "$API"; then
    echo "  ✓ $API enabled"
else
    echo "  ✗ $API not enabled"
fi

#check service account
if gcloud iam service-accounts describe "$SA_EMAIL" &> /dev/null; then
    echo "  ✓ Service account exists"
else
    echo "  ✗ Service account not found"
fi

#check key file
if [ -f "$KEY_FILE" ]; then
    echo "  ✓ Key file exists: $KEY_FILE"
else
    echo "  ✗ Key file not found"
fi

#summary
echo ""
echo "================================"
echo "GCP Setup Complete!"
echo "================================"
echo ""
echo "Project ID: $PROJECT_ID"
echo "Service Account: $SA_EMAIL"
echo "Key File: $KEY_FILE"
echo ""
echo "Next steps:"
echo "  1. Run: ./scripts/setup-github-secrets.sh"
echo "  2. Create .env file: cp .env.example .env"
echo "  3. Update .env with:"
echo "     GOOGLE_CLOUD_PROJECT=$PROJECT_ID"
echo "     GOOGLE_APPLICATION_CREDENTIALS=$KEY_FILE"
echo ""
echo "Save these values:"
echo "export GOOGLE_CLOUD_PROJECT=$PROJECT_ID"
echo "export GOOGLE_CLOUD_LOCATION=us-central1"
echo "export GOOGLE_APPLICATION_CREDENTIALS=$KEY_FILE"
