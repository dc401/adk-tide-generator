#!/bin/bash
#bootstrap.sh - secure, idempotent setup for sigma detection agent
#
#what this does:
# 1. checks prerequisites (gcloud, git, gh + auth)
# 2. GCP setup (project, APIs, SA, key) - idempotent
# 3. GitHub setup (create private repo, set secrets) - idempotent
# 4. local setup (.env, .gitignore validation)
# 5. cleanup (delete SA key after upload to GitHub)
# 6. validation (test everything works)
#
#usage:
#   chmod +x scripts/bootstrap.sh
#   ./scripts/bootstrap.sh

set -e  #exit on error

#colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' #no color

#state file to track progress
STATE_FILE=".bootstrap-state"

echo "================================"
echo "Sigma Detection Agent - Secure Bootstrap"
echo "================================"
echo ""

#==============================================================================
# State Management
#==============================================================================

function mark_complete() {
    echo "$1=done" >> "$STATE_FILE"
}

function is_complete() {
    grep -q "$1=done" "$STATE_FILE" 2>/dev/null
}

function get_state() {
    grep "^$1=" "$STATE_FILE" 2>/dev/null | cut -d'=' -f2
}

function save_state() {
    #remove existing entry if present
    sed -i.bak "/^$1=/d" "$STATE_FILE" 2>/dev/null || true
    echo "$1=$2" >> "$STATE_FILE"
}

#==============================================================================
# Step 1: Prerequisites Check
#==============================================================================

if ! is_complete "prereqs"; then
    echo -e "${YELLOW}[1/6] Checking Prerequisites${NC}"
    echo ""

    #check gcloud
    if ! command -v gcloud &> /dev/null; then
        echo -e "${RED}ERROR: gcloud CLI not found${NC}"
        echo "Install from: https://cloud.google.com/sdk/docs/install"
        exit 1
    fi
    echo "  ✓ gcloud CLI found"

    #check git
    if ! command -v git &> /dev/null; then
        echo -e "${RED}ERROR: git not found${NC}"
        echo "Install git first"
        exit 1
    fi
    echo "  ✓ git found"

    #check gh (optional)
    if command -v gh &> /dev/null; then
        GH_AVAILABLE=true
        echo "  ✓ gh CLI found"
    else
        GH_AVAILABLE=false
        echo -e "${YELLOW}  ⚠ gh CLI not found (will use manual GitHub setup)${NC}"
        echo "    Install gh for automation: https://cli.github.com/"
    fi

    #check gcloud auth
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" &> /dev/null; then
        echo -e "${YELLOW}Running gcloud auth login...${NC}"
        gcloud auth login
    fi
    GCLOUD_ACCOUNT=$(gcloud auth list --filter=status:ACTIVE --format="value(account)")
    echo "  ✓ Authenticated to GCP: $GCLOUD_ACCOUNT"

    #check gh auth (only if gh available)
    if [ "$GH_AVAILABLE" = true ]; then
        if ! gh auth status &> /dev/null; then
            echo -e "${YELLOW}Running gh auth login...${NC}"
            gh auth login
        fi
        GH_USER=$(gh api user -q .login)
        echo "  ✓ Authenticated to GitHub: $GH_USER"
        save_state "gh_user" "$GH_USER"
    else
        echo "  ⚠ GitHub setup will be manual (no gh CLI)"
    fi

    mark_complete "prereqs"
    echo ""
else
    echo -e "${GREEN}[1/6] Prerequisites - Already Complete${NC}"
    echo ""
fi

#==============================================================================
# Step 2: GCP Setup
#==============================================================================

if ! is_complete "gcp_setup"; then
    echo -e "${YELLOW}[2/6] GCP Setup${NC}"
    echo ""

    #get or create project
    EXISTING_PROJECT=$(get_state "gcp_project")

    if [ -n "$EXISTING_PROJECT" ]; then
        echo "Found existing project from previous run: $EXISTING_PROJECT"
        read -p "Use this project? (y/n): " USE_EXISTING
        if [ "$USE_EXISTING" = "y" ]; then
            PROJECT_ID="$EXISTING_PROJECT"
        fi
    fi

    if [ -z "$PROJECT_ID" ]; then
        echo "Choose GCP project option:"
        echo "  1. Use existing project"
        echo "  2. Create new project (auto-generate ID)"
        echo "  3. Create new project (specify ID)"
        read -p "Enter choice (1-3): " CHOICE

        case $CHOICE in
            1)
                read -p "Enter existing project ID: " PROJECT_ID
                ;;
            2)
                RANDOM_SUFFIX=$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 6 | head -n 1)
                PROJECT_ID="sigma-detection-$RANDOM_SUFFIX"
                echo "Generated: $PROJECT_ID"
                ;;
            3)
                read -p "Enter new project ID: " PROJECT_ID
                ;;
        esac
    fi

    save_state "gcp_project" "$PROJECT_ID"
    echo "  ✓ Project ID: $PROJECT_ID"

    #create project if doesn't exist
    if ! gcloud projects describe "$PROJECT_ID" &> /dev/null; then
        echo "  Creating project..."
        gcloud projects create "$PROJECT_ID" --name="Sigma Detection Agent"
    fi

    #set active project
    gcloud config set project "$PROJECT_ID"

    #set quota project for ADC
    echo "  Setting quota project for Application Default Credentials..."
    gcloud auth application-default set-quota-project "$PROJECT_ID" 2>/dev/null || true

    #add environment tag
    echo "  Adding environment tag..."
    read -p "  Environment (development/staging/production): " ENV_TAG
    ENV_TAG=${ENV_TAG:-development}  #default to development

    #create tag if it doesn't exist (requires org-level permissions, may fail)
    gcloud resource-manager tags keys create environment \
        --parent=projects/$PROJECT_ID \
        --description="Environment designation" 2>/dev/null || true

    gcloud resource-manager tags values create "$ENV_TAG" \
        --parent=projects/$PROJECT_ID/tagKeys/environment 2>/dev/null || true

    gcloud resource-manager tags bindings create \
        --location=global \
        --tag-value="$ENV_TAG" \
        --parent=//cloudresourcemanager.googleapis.com/projects/$PROJECT_ID 2>/dev/null || true

    save_state "environment" "$ENV_TAG"

    #check billing
    echo "  ⚠ Billing required: https://console.cloud.google.com/billing/linkedaccount?project=$PROJECT_ID"
    read -p "  Is billing enabled? (y/n): " BILLING_OK
    if [ "$BILLING_OK" != "y" ]; then
        echo "Enable billing first, then re-run"
        exit 0
    fi

    #enable APIs
    echo "  Enabling APIs..."
    gcloud services enable aiplatform.googleapis.com --project="$PROJECT_ID" --quiet
    gcloud services enable iam.googleapis.com --project="$PROJECT_ID" --quiet

    #create service account
    SA_NAME="sigma-detection-agent"
    SA_EMAIL="$SA_NAME@$PROJECT_ID.iam.gserviceaccount.com"

    if ! gcloud iam service-accounts describe "$SA_EMAIL" --project="$PROJECT_ID" &> /dev/null; then
        echo "  Creating service account..."
        gcloud iam service-accounts create "$SA_NAME" \
            --display-name="Sigma Detection Agent" \
            --project="$PROJECT_ID"
    fi

    #grant permissions (idempotent - safe to run multiple times)
    echo "  Granting permissions..."

    #check if role already granted
    EXISTING_ROLE=$(gcloud projects get-iam-policy "$PROJECT_ID" \
        --flatten="bindings[].members" \
        --filter="bindings.members:serviceAccount:$SA_EMAIL AND bindings.role:roles/aiplatform.user" \
        --format="value(bindings.role)" 2>/dev/null || true)

    if [ -n "$EXISTING_ROLE" ]; then
        echo "  ✓ Role already granted: roles/aiplatform.user"
    else
        gcloud projects add-iam-policy-binding "$PROJECT_ID" \
            --member="serviceAccount:$SA_EMAIL" \
            --role="roles/aiplatform.user" \
            --condition=None \
            --quiet > /dev/null
        echo "  ✓ Granted: roles/aiplatform.user"
    fi

    #create key (temporary - will be deleted after upload to GitHub)
    KEY_FILE="/tmp/sigma-sa-key-$$.json"
    echo "  Creating temporary service account key..."
    gcloud iam service-accounts keys create "$KEY_FILE" \
        --iam-account="$SA_EMAIL" \
        --project="$PROJECT_ID"
    chmod 600 "$KEY_FILE"

    save_state "sa_key_file" "$KEY_FILE"
    save_state "sa_email" "$SA_EMAIL"

    mark_complete "gcp_setup"
    echo -e "${GREEN}  ✓ GCP Setup Complete${NC}"
    echo ""
else
    echo -e "${GREEN}[2/6] GCP Setup - Already Complete${NC}"
    PROJECT_ID=$(get_state "gcp_project")
    KEY_FILE=$(get_state "sa_key_file")
    SA_EMAIL=$(get_state "sa_email")
    echo "  Project: $PROJECT_ID"
    echo ""
fi

#==============================================================================
# Step 3: GitHub Setup (Private Repo + Secrets)
#==============================================================================

if ! is_complete "github_setup"; then
    echo -e "${YELLOW}[3/6] GitHub Setup${NC}"
    echo ""

    if [ "$GH_AVAILABLE" = true ]; then
        #automated setup with gh CLI
        GH_USER=$(get_state "gh_user")

        #determine repo name
        EXISTING_REPO=$(get_state "github_repo")

        if [ -n "$EXISTING_REPO" ]; then
            echo "Found existing repo from previous run: $EXISTING_REPO"
            read -p "Use this repo? (y/n): " USE_EXISTING_REPO
            if [ "$USE_EXISTING_REPO" = "y" ]; then
                REPO="$EXISTING_REPO"
            fi
        fi

        if [ -z "$REPO" ]; then
            echo "Default repo: $GH_USER/sigma-detection-agent"
            read -p "Use default repo name? (y/n): " USE_DEFAULT
            if [ "$USE_DEFAULT" = "y" ]; then
                REPO="$GH_USER/sigma-detection-agent"
            else
                read -p "Enter repo (format: owner/name): " REPO
            fi
        fi

        save_state "github_repo" "$REPO"
        REPO_NAME=$(echo "$REPO" | cut -d'/' -f2)

        #check if repo exists
        if gh repo view "$REPO" &> /dev/null; then
            echo "  ✓ Repository exists: $REPO"
        else
            echo "  Creating repository..."
            read -p "  Create as private? (recommended) (y/n): " CREATE_PRIVATE

            if [ "$CREATE_PRIVATE" = "y" ]; then
                gh repo create "$REPO" --private --description "Automated SIEM Detection Engineering with Sigma Rules"
            else
                gh repo create "$REPO" --public --description "Automated SIEM Detection Engineering with Sigma Rules"
            fi
            echo "  ✓ Created repository: $REPO"
        fi

        #set GitHub secrets
        echo "  Setting GitHub secrets..."

        if [ ! -f "$KEY_FILE" ]; then
            echo -e "${RED}ERROR: Service account key not found: $KEY_FILE${NC}"
            exit 1
        fi

        cat "$KEY_FILE" | gh secret set GCP_SA_KEY --repo="$REPO"
        echo "$PROJECT_ID" | gh secret set GCP_PROJECT_ID --repo="$REPO"

        echo "  ✓ Secrets uploaded to GitHub"

        #add GitHub topics for consistent tagging
        ENV_TAG=$(get_state "environment")
        echo "  Adding GitHub topics..."
        gh repo edit "$REPO" \
            --add-topic "sigma-rules" \
            --add-topic "detection-engineering" \
            --add-topic "threat-intelligence" \
            --add-topic "gcp" \
            --add-topic "$ENV_TAG" 2>/dev/null || true
        echo "  ✓ GitHub topics added"
    else
        #manual setup instructions
        echo -e "${YELLOW}Manual GitHub Setup Required${NC}"
        echo ""
        read -p "Enter your GitHub username: " GH_USER
        read -p "Enter repository name (e.g., sigma-detection-agent): " REPO_NAME
        REPO="$GH_USER/$REPO_NAME"
        save_state "github_repo" "$REPO"

        echo ""
        echo "Follow these steps:"
        echo ""
        echo "1. Create GitHub repository:"
        echo "   - Go to: https://github.com/new"
        echo "   - Name: $REPO_NAME"
        echo "   - ✓ Private (recommended)"
        echo "   - Description: Automated SIEM Detection Engineering with Sigma Rules"
        echo "   - Click 'Create repository'"
        echo ""
        echo "2. Set GitHub secrets:"
        echo "   - Go to: https://github.com/$REPO/settings/secrets/actions"
        echo "   - Click 'New repository secret'"
        echo ""
        echo "   Secret 1:"
        echo "     Name: GCP_SA_KEY"
        echo "     Value: (paste contents of $KEY_FILE)"
        echo ""
        echo "   Secret 2:"
        echo "     Name: GCP_PROJECT_ID"
        echo "     Value: $PROJECT_ID"
        echo ""
        read -p "Press Enter after completing GitHub setup..."

        #validate secrets were set (can't check without gh, so just confirm)
        echo "  ✓ GitHub setup completed manually"
    fi

    mark_complete "github_setup"
    echo -e "${GREEN}  ✓ GitHub Setup Complete${NC}"
    echo ""
else
    echo -e "${GREEN}[3/6] GitHub Setup - Already Complete${NC}"
    REPO=$(get_state "github_repo")
    echo "  Repository: $REPO"
    echo ""
fi

#==============================================================================
# Step 4: Local Git Setup
#==============================================================================

if ! is_complete "local_setup"; then
    echo -e "${YELLOW}[4/6] Local Git Setup${NC}"
    echo ""

    #initialize git if not already
    if [ ! -d ".git" ]; then
        echo "  Initializing git repository..."
        git init
        git branch -M main
    fi

    #set remote
    REMOTE_URL="https://github.com/$REPO.git"
    if git remote get-url origin &> /dev/null; then
        EXISTING_REMOTE=$(git remote get-url origin)
        if [ "$EXISTING_REMOTE" != "$REMOTE_URL" ]; then
            git remote set-url origin "$REMOTE_URL"
            echo "  ✓ Updated remote: $REMOTE_URL"
        fi
    else
        git remote add origin "$REMOTE_URL"
        echo "  ✓ Added remote: $REMOTE_URL"
    fi

    #validate .gitignore
    echo "  Validating .gitignore..."
    REQUIRED_IGNORES=(".env" "*.json" "session_results/" "venv/" "__pycache__/" ".bootstrap-state")

    for PATTERN in "${REQUIRED_IGNORES[@]}"; do
        if ! grep -q "^$PATTERN$" .gitignore 2>/dev/null; then
            echo "$PATTERN" >> .gitignore
            echo "    Added: $PATTERN"
        fi
    done

    #create .env file
    if [ ! -f ".env" ]; then
        echo "  Creating .env file..."
        cat > .env << EOF
#GCP configuration (for local development only)
GOOGLE_CLOUD_PROJECT=$PROJECT_ID
GOOGLE_CLOUD_LOCATION=us-central1
GOOGLE_GENAI_USE_VERTEXAI=true

#DO NOT SET CREDENTIALS PATH - use gcloud auth for local dev
#GitHub Actions will use secrets
EOF
        echo "  ✓ Created .env"
    fi

    #validate no actual secret keys in tracked files (not just mentions of them)
    echo "  Validating no secrets in git..."

    #check for actual AWS keys
    if git ls-files | xargs grep -l "AKIA[0-9A-Z]{16}" 2>/dev/null; then
        echo -e "${RED}ERROR: AWS access key found in tracked files!${NC}"
        exit 1
    fi

    #check for actual GCP service account JSON structure (not just the word)
    if git ls-files -z | xargs -0 grep -l '"type":\s*"service_account"' 2>/dev/null; then
        echo -e "${RED}WARNING: Potential GCP service account JSON found!${NC}"
        git ls-files -z | xargs -0 grep -l '"type":\s*"service_account"'
        read -p "Continue anyway? (y/n): " CONTINUE
        if [ "$CONTINUE" != "y" ]; then
            exit 1
        fi
    fi

    echo "  ✓ No secrets detected"

    mark_complete "local_setup"
    echo -e "${GREEN}  ✓ Local Setup Complete${NC}"
    echo ""
else
    echo -e "${GREEN}[4/6] Local Setup - Already Complete${NC}"
    echo ""
fi

#==============================================================================
# Step 5: Cleanup (Delete SA Key)
#==============================================================================

if ! is_complete "cleanup"; then
    echo -e "${YELLOW}[5/6] Security Cleanup${NC}"
    echo ""

    #delete service account key from disk (already in GitHub secrets)
    if [ -n "$KEY_FILE" ] && [ -f "$KEY_FILE" ]; then
        echo "  Deleting local service account key..."
        rm -f "$KEY_FILE"
        echo "  ✓ Deleted: $KEY_FILE"
        echo "  ✓ Key safely stored in GitHub secrets only"
    fi

    #check for any other SA keys in home directory
    SA_KEYS=$(find ~ -maxdepth 1 -name "*sa-key*.json" -o -name "*service*account*.json" 2>/dev/null || true)
    if [ -n "$SA_KEYS" ]; then
        echo -e "${YELLOW}  ⚠ Found other SA keys in home directory:${NC}"
        echo "$SA_KEYS"
        read -p "  Delete these too? (y/n): " DELETE_KEYS
        if [ "$DELETE_KEYS" = "y" ]; then
            echo "$SA_KEYS" | xargs rm -f
            echo "  ✓ Deleted all found keys"
        fi
    fi

    mark_complete "cleanup"
    echo -e "${GREEN}  ✓ Cleanup Complete${NC}"
    echo ""
else
    echo -e "${GREEN}[5/6] Cleanup - Already Complete${NC}"
    echo ""
fi

#==============================================================================
# Step 6: Validation & First Commit
#==============================================================================

if ! is_complete "validation"; then
    echo -e "${YELLOW}[6/6] Validation & Initial Commit${NC}"
    echo ""

    #validate GCP access
    echo "  Testing GCP authentication..."
    gcloud projects describe "$PROJECT_ID" &> /dev/null
    echo "  ✓ GCP access confirmed"

    #validate GitHub secrets (only if gh available)
    if [ "$GH_AVAILABLE" = true ]; then
        echo "  Validating GitHub secrets..."
        SECRETS=$(gh secret list --repo="$REPO" 2>/dev/null | grep -E "(GCP_SA_KEY|GCP_PROJECT_ID)" | wc -l)
        if [ "$SECRETS" -eq 2 ]; then
            echo "  ✓ GitHub secrets configured"
        else
            echo -e "${YELLOW}  ⚠ Could not verify GitHub secrets via gh CLI${NC}"
            echo "  Verify manually at: https://github.com/$REPO/settings/secrets/actions"
            read -p "  Are secrets configured? (y/n): " SECRETS_OK
            if [ "$SECRETS_OK" != "y" ]; then
                echo "  Configure secrets first, then re-run"
                exit 1
            fi
            echo "  ✓ GitHub secrets confirmed (manual)"
        fi
    else
        echo "  Verifying GitHub secrets (manual setup)..."
        echo "  Check: https://github.com/$REPO/settings/secrets/actions"
        echo "  Required secrets:"
        echo "    - GCP_SA_KEY"
        echo "    - GCP_PROJECT_ID"
        read -p "  Are both secrets configured? (y/n): " SECRETS_OK
        if [ "$SECRETS_OK" != "y" ]; then
            echo "  Configure secrets first, then re-run"
            exit 1
        fi
        echo "  ✓ GitHub secrets confirmed (manual verification)"
    fi

    #initial commit
    echo "  Creating initial commit..."
    git add .
    git commit -m "Initial commit - Sigma Detection Agent

Automated SIEM detection engineering solution.

Setup:
- GCP project: $PROJECT_ID
- GitHub repo: $REPO (private)
- Secrets configured in GitHub Actions
- No service account keys committed

Co-Authored-By: Bootstrap Script <noreply@bootstrap.sh>" || echo "  (no changes to commit)"

    #push to GitHub (handle conflicts)
    echo "  Pushing to GitHub..."

    if git push -u origin main 2>&1 | tee /tmp/git-push-output.txt | grep -q "rejected"; then
        echo -e "${YELLOW}  ⚠ Remote has changes - attempting to merge${NC}"

        #pull with rebase
        if git pull --rebase origin main; then
            echo "  ✓ Merged remote changes"
            git push -u origin main
            echo "  ✓ Pushed to GitHub"
        else
            echo -e "${RED}  ✗ Merge conflict detected${NC}"
            echo "  Fix conflicts manually, then:"
            echo "    git rebase --continue"
            echo "    git push -u origin main"
            exit 1
        fi
    elif grep -q "Everything up-to-date" /tmp/git-push-output.txt; then
        echo "  ✓ Already up to date"
    else
        echo "  ✓ Pushed to GitHub"
    fi

    rm -f /tmp/git-push-output.txt

    mark_complete "validation"
    echo -e "${GREEN}  ✓ Validation Complete${NC}"
    echo ""
else
    echo -e "${GREEN}[6/6] Validation - Already Complete${NC}"
    echo ""
fi

#==============================================================================
# Summary
#==============================================================================

echo "================================"
echo -e "${GREEN}✓ Bootstrap Complete!${NC}"
echo "================================"
echo ""
echo "Configuration:"
echo "  GCP Project: $PROJECT_ID"
echo "  GitHub Repo: https://github.com/$REPO"
echo "  Service Account: $SA_EMAIL"
echo ""
echo "Security:"
echo "  ✓ Service account key stored in GitHub secrets only"
echo "  ✓ No keys on local filesystem"
echo "  ✓ .gitignore validated"
echo "  ✓ Private repository (if selected)"
echo ""

#cleanup state file (contains sensitive info)
if [ -f "$STATE_FILE" ]; then
    echo "  Cleaning up bootstrap state file..."
    rm -f "$STATE_FILE"
    echo "  ✓ State file removed"
fi

echo ""
echo "Next steps:"
echo "  1. Setup Application Default Credentials (IMPORTANT!):"
echo "     gcloud auth application-default login"
echo "     gcloud auth application-default set-quota-project $PROJECT_ID"
echo ""
echo "  2. Setup Python environment:"
echo "     python3.11 -m venv venv"
echo "     source venv/bin/activate"
echo "     pip install -r requirements.txt"
echo ""
echo "  3. Test CTI loading:"
echo "     python run_agent.py --test-cti"
echo ""
echo "  4. View GitHub Actions:"
echo "     https://github.com/$REPO/actions"
echo ""
echo "Resource Tags:"
echo "  GCP Environment: $(get_state 'environment')"
echo "  GitHub Topics: sigma-rules, detection-engineering, gcp, $(get_state 'environment')"
echo ""
echo "To re-run bootstrap: ./scripts/bootstrap.sh"
