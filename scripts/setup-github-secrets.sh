#!/bin/bash
#setup GitHub secrets for CI/CD pipeline

set -e

echo "===================================="
echo "GitHub Secrets Setup"
echo "===================================="
echo ""

#check if gh is installed
if ! command -v gh &> /dev/null; then
    echo "ERROR: GitHub CLI (gh) is not installed"
    echo ""
    echo "Install instructions:"
    echo "  macOS:   brew install gh"
    echo "  Linux:   See https://cli.github.com/manual/installation"
    echo ""
    exit 1
fi

#check authentication
if ! gh auth status &> /dev/null; then
    echo "Not authenticated. Running gh auth login..."
    gh auth login
fi

#get repository
REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || echo "")
if [ -z "$REPO" ]; then
    echo "ERROR: Could not detect repository"
    exit 1
fi

echo "Repository: $REPO"

#get GCP project ID
PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-$(gcloud config get-value project 2>/dev/null)}"
if [ -z "$PROJECT_ID" ]; then
    echo "ERROR: GCP project ID not set"
    echo "Run: gcloud config set project YOUR_PROJECT_ID"
    exit 1
fi

echo "Project ID: $PROJECT_ID"

#find service account key
KEY_FILE="$HOME/sigma-detection-sa-key.json"
if [ ! -f "$KEY_FILE" ]; then
    read -p "Enter path to service account key: " KEY_FILE
fi

if [ ! -f "$KEY_FILE" ]; then
    echo "ERROR: Service account key not found"
    exit 1
fi

#set secrets
echo ""
echo "Setting secrets..."
echo "$PROJECT_ID" | gh secret set GCP_PROJECT_ID
echo "$PROJECT_ID" | gh secret set GOOGLE_CLOUD_PROJECT
echo "us-central1" | gh secret set GOOGLE_CLOUD_LOCATION
cat "$KEY_FILE" | gh secret set GCP_SA_KEY

echo ""
echo "✓ Secrets configured for $REPO"
gh secret list
