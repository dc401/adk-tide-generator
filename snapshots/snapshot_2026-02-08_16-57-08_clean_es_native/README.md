# Elasticsearch Detection Agent - Automated SIEM Detection Engineering

Production-ready automated detection engineering solution that converts CTI intelligence → Elasticsearch Detection Rules with comprehensive multi-level validation and self-healing refinement.

## Features

- **Native Elasticsearch Format:** Detection rules in Elasticsearch Detection API format (Lucene queries + ECS fields)
- **Multi-Level Smart Refinement:** Auto-fixes rules at validation, integration test, and LLM judge stages
- **Automated Testing:** 3-stage validation + integration testing with native Elasticsearch
- **Empirical LLM Judge:** Quality evaluation based on actual SIEM test results
- **YAML-First I/O:** All rules and outputs in YAML (easier for LLMs and humans)
- **Security Hardened:** OWASP LLM Top 10 protection, input validation, output sanitization
- **GitHub-Only Infrastructure:** No persistent cloud resources required

## Architecture

```
CTI Files → Detection Agent → Elasticsearch Detection Rules (YAML)
                                        ↓
            STAGE 1: Validation (with auto-refinement)
            ├─ Lucene syntax check
            ├─ YAML → JSON conversion
            └─ LLM schema validator (research-backed)
                                        ↓
            STAGE 2: Integration Testing (with auto-refinement)
            ├─ Deploy to native Elasticsearch
            ├─ Ingest TP/FN/FP/TN test payloads
            ├─ Calculate precision/recall metrics
            └─ Smart decision: Fix QUERY or TEST CASES
                                        ↓
            STAGE 3: LLM Judge (with auto-refinement)
            ├─ Empirical evaluation (actual test results)
            ├─ Quality scoring (≥0.70 threshold)
            └─ Deployment decision: APPROVE/REFINE/REJECT
                                        ↓
                    Human Review → Production
```

## Prerequisites

- Python 3.11+ (3.12 or 3.13 recommended)
- GCP account with Vertex AI enabled (for Gemini API)
- GitHub account (for CI/CD)
- git CLI
- gcloud CLI ([installation guide](https://cloud.google.com/sdk/docs/install))

**Note:** Elasticsearch is installed automatically via native packages during integration testing (no Docker required).

## Quick Setup

### Option 1: Automated Bootstrap (Recommended)

```bash
#clone and navigate to project
git clone https://github.com/yourusername/adk-tide-generator.git
cd adk-tide-generator

#run interactive bootstrap
chmod +x scripts/bootstrap.sh
./scripts/bootstrap.sh
```

The bootstrap script will:
1. Set up Python virtual environment
2. Install dependencies
3. Configure GCP credentials
4. Set up GitHub secrets
5. Validate the installation

### Option 2: Manual Setup

```bash
#1. create virtual environment
python3.11 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

#2. install dependencies
pip install --upgrade pip
pip install -r requirements.txt

#3. configure GCP
export GOOGLE_CLOUD_PROJECT="your-project-id"
gcloud auth application-default login

#4. add CTI files
mkdir -p cti_src
cp your-threat-intel.pdf cti_src/

#5. test CTI loading
python run_agent.py --test-cti

#6. generate detection rules
python run_agent.py --interactive
```

## Usage

### Interactive Mode (Local)

```bash
python run_agent.py --interactive
```

Prompts you for:
- CTI folder location
- Output directory
- GCP project ID
- Confirmation before generation

### Non-Interactive Mode (CI/CD)

```bash
python run_agent.py \
  --cti-folder cti_src \
  --output generated \
  --project YOUR_GCP_PROJECT
```

### With Self-Healing Refinement (Default)

```bash
#refinement enabled by default (max 3 iterations if 0 rules pass)
python run_agent.py --cti-folder cti_src --output generated
```

### Disable Refinement (for testing)

```bash
python run_agent.py --cti-folder cti_src --output generated --no-refinement
```

## Validation & Testing

### Stage 1: Pre-Integration Validation

```bash
python scripts/validate_rules.py \
  --rules-dir generated/detection_rules \
  --staging-dir generated/staging \
  --project YOUR_GCP_PROJECT
```

Validates:
- Lucene syntax (deterministic)
- YAML → JSON conversion
- LLM schema validation (research-backed)

Auto-refines up to 2 times per rule if failures occur.

### Stage 2: Integration Testing

```bash
python scripts/integration_test_ci.py \
  --rules-dir generated/detection_rules \
  --project YOUR_GCP_PROJECT
```

Tests:
- Deploys rules to native Elasticsearch
- Ingests TP/FN/FP/TN test payloads
- Calculates precision/recall
- Smart decision: Fix query OR test cases

Requires:
- Precision ≥ 0.80 (max 20% false positives)
- Recall ≥ 0.70 (catch at least 70% of attacks)

### Stage 3: LLM Judge Evaluation

```bash
python scripts/run_llm_judge.py \
  --rules-dir generated/detection_rules \
  --test-results integration_test_results.yml \
  --project YOUR_GCP_PROJECT
```

Evaluates:
- Quality score based on actual test results
- Deployment recommendation (APPROVE/REFINE/REJECT)
- Refines based on judge feedback if needed

## Multi-Level Refinement System

The system automatically refines rules at each failure stage:

### Validation Refinement
- **Trigger:** Lucene syntax errors, schema violations
- **Fix:** Corrects operators, ECS field names, MITRE references
- **Attempts:** Max 2 per rule

### Integration Test Refinement
- **Trigger:** Precision < 0.80 or Recall < 0.70
- **Smart Decision:** Analyzes if QUERY or TEST CASES need fixing
- **Fix:** Refines query logic OR updates test payloads
- **Attempts:** Max 2 per rule

### Judge Refinement
- **Trigger:** Deployment decision = REFINE
- **Fix:** Applies judge's specific recommendations
- **Attempts:** Max 2 per rule

See [MULTI_LEVEL_REFINEMENT.md](MULTI_LEVEL_REFINEMENT.md) for detailed documentation.

## Project Structure

```
adk-tide-generator/
├── detection_agent/               #core detection generation logic
│   ├── agent.py                   #main detection agent (5 stages)
│   ├── refinement.py              #pipeline-level refinement wrapper
│   ├── per_rule_refinement.py     #granular per-rule refinement
│   ├── prompts/                   #LLM prompts (external files)
│   │   ├── security_guard.md      #OWASP LLM Top 10 protection
│   │   ├── detection_generator.md #rule generation with research
│   │   ├── validator.md           #rule validation with research
│   │   └── evaluator.md           #test case generation
│   ├── schemas/                   #Pydantic schemas
│   │   └── detection_rule.py      #ES Detection Rule schema
│   └── tools/                     #custom tools
│       └── load_cti_files.py      #CTI file loader (PDF/DOCX/TXT/MD)
│
├── scripts/                       #validation and testing scripts
│   ├── bootstrap.sh               #interactive setup script
│   ├── validate_rules.py          #3-stage validation with refinement
│   ├── integration_test_ci.py     #ES integration testing with refinement
│   ├── run_llm_judge.py           #empirical LLM judge with refinement
│   ├── cleanup_staging.sh         #clean temp artifacts
│   ├── setup-gcp.sh               #GCP setup helper
│   └── setup-github-secrets.sh    #GitHub secrets helper
│
├── .github/workflows/             #CI/CD workflows
│   └── generate-detections.yml    #main workflow (CTI → rules)
│
├── cti_src/                       #CTI input files
│   └── sample_cti.md              #example CTI file
│
├── generated/                     #agent outputs
│   ├── detection_rules/           #generated YAML rules
│   ├── cti_context.yml            #CTI analysis context
│   └── staging/                   #temp validation artifacts (gitignored)
│
├── run_agent.py                   #CLI entry point
├── requirements.txt               #Python dependencies
├── PROGRESS.md                    #development progress tracking
├── TESTING_GUIDE.md               #testing documentation
└── MULTI_LEVEL_REFINEMENT.md      #refinement system docs
```

## GitHub Actions Workflow

The main workflow (`.github/workflows/generate-detections.yml`) triggers on:
- Manual dispatch
- Push to `main` with CTI changes in `cti_src/`

Workflow steps:
1. Clean stale artifacts
2. Install dependencies
3. Authenticate to GCP
4. Check CTI files (security validation)
5. Run detection agent with refinement
6. Verify rule generation
7. Commit generated rules back to repo

## Security Features

### OWASP LLM Top 10 Protection
- Scans CTI for prompt injection patterns
- Blocks jailbreak attempts
- Detects data poisoning
- Validates output for manipulation

### Input Validation
- File size limits (max 50MB per file)
- Path traversal prevention
- Allowed file extensions only (.pdf, .txt, .md, .docx)
- Suspicious filename detection

### Output Sanitization
- Removes injection patterns from generated rules
- Validates Lucene syntax before writing
- Schema validation with research grounding

## Cost Optimization

### Model Selection
- **Gemini 2.5 Flash:** Rule generation (fast, cheap)
- **Gemini 2.5 Pro:** Validation and judging (accurate)

### Quota Management
- Inter-agent delay: 3.0s
- Aggressive retry backoff
- Session-level retry with exponential backoff
- Max 3 pipeline iterations if 0 rules pass

### Token Efficiency
- External prompts (no inline repetition)
- Truncated outputs (120k char limit)
- State pruning between stages

## Testing

### Unit Tests
```bash
#test CTI loading
python run_agent.py --test-cti

#test validation only
python scripts/validate_rules.py --rules-dir generated/detection_rules
```

### Integration Tests
```bash
#test with native Elasticsearch
python scripts/integration_test_ci.py \
  --rules-dir generated/detection_rules \
  --skip-install  #if ES already installed
```

### End-to-End Test
```bash
#complete pipeline
python run_agent.py --cti-folder cti_src --output generated
python scripts/validate_rules.py --rules-dir generated/detection_rules
python scripts/integration_test_ci.py --rules-dir generated/detection_rules
python scripts/run_llm_judge.py --rules-dir generated/detection_rules
```

## Troubleshooting

### GCP Authentication Errors
```bash
#re-authenticate
gcloud auth application-default login

#verify project
gcloud config get-value project
```

### Quota Exhaustion
```bash
#check quota usage
gcloud alpha services quota list \
  --service=aiplatform.googleapis.com \
  --filter="metric.type:aiplatform.googleapis.com/quota/generate_content_requests_per_minute_per_project_per_region"

#increase delay between agents (edit detection_agent/agent.py)
INTER_AGENT_DELAY = 5.0  # increase from 3.0
```

### Rule Generation Failures
```bash
#enable verbose logging
export PYTHONUNBUFFERED=1
python run_agent.py --interactive

#disable refinement for debugging
python run_agent.py --interactive --no-refinement
```

### Integration Test Failures
```bash
#check Elasticsearch status
curl http://localhost:9200/_cluster/health

#manually restart ES
sudo systemctl restart elasticsearch
```

## Documentation

- [PROGRESS.md](PROGRESS.md) - Development progress and status
- [TESTING_GUIDE.md](TESTING_GUIDE.md) - Comprehensive testing procedures
- [MULTI_LEVEL_REFINEMENT.md](MULTI_LEVEL_REFINEMENT.md) - Refinement system architecture
- [ARCHITECTURE_ELASTICSEARCH_NATIVE.md](ARCHITECTURE_ELASTICSEARCH_NATIVE.md) - Technical architecture details

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly (unit + integration)
5. Submit a pull request

## License

MIT License - See LICENSE file for details

## Support

For issues and questions:
- GitHub Issues: https://github.com/yourusername/adk-tide-generator/issues
- Documentation: See docs/ folder

## Acknowledgments

Built with:
- Google Gemini 2.5 (Flash & Pro) via Vertex AI
- Elasticsearch Detection Rule API
- ECS (Elastic Common Schema)
- luqum (Lucene query parser)
- Pydantic (schema validation)
