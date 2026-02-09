# Elasticsearch Detection Agent - Automated SIEM Detection Engineering

Production-ready automated detection engineering solution that converts CTI intelligence → Elasticsearch Detection Rules with comprehensive multi-level validation, TTP-aligned testing, and self-healing refinement.

## Features

- **Native Elasticsearch Format:** Detection rules in Elasticsearch Detection API format (Lucene queries + ECS fields)
- **Multi-Level Smart Refinement:** Auto-fixes rules at validation, integration test, and LLM judge stages
- **TTP Intent Validation:** Gemini-powered validation ensures test payloads match real-world attack patterns
- **End-to-End Testing:** Single-command pipeline testing with comprehensive reporting
- **Automated Testing:** 3-stage validation + integration testing with ephemeral Elasticsearch (Docker)
- **Empirical LLM Judge:** Quality evaluation based on actual SIEM test results
- **YAML-First I/O:** All rules and outputs in YAML (easier for LLMs and humans)
- **Security Hardened:** OWASP LLM Top 10 protection, input validation, output sanitization
- **GitHub-Only Infrastructure:** No persistent cloud resources required

## Automatic Region Rotation

**Quota Management:** The system automatically rotates through 8 GCP Vertex AI regions to distribute API quota usage and avoid exhaustion.

**Regions:**
- us-central1
- global
- us-south1
- us-east5
- us-west1
- us-east1
- us-east4
- us-west4

**How It Works:**
- Region selected automatically based on current UTC hour
- Rotates every hour (24-hour cycle covers all regions 3 times)
- Same region used throughout entire pipeline run
- No manual configuration needed
- 8x quota capacity vs single region

**Example:**
```
Hour 00, 08, 16 UTC → us-central1
Hour 01, 09, 17 UTC → global
Hour 02, 10, 18 UTC → us-south1
...and so on
```

This means you can run the pipeline multiple times per day without hitting quota limits, as each hour uses a different region's quota pool.

## Architecture

```
CTI Files → Detection Agent → Elasticsearch Detection Rules (YAML)
                                        ↓
            STAGE 1: Validation (with auto-refinement)
            ├─ Lucene syntax check
            ├─ ECS field validation (1990 fields)
            ├─ Iterative field research (3 attempts)
            └─ LLM schema validator (research-backed)
                                        ↓
            STAGE 2: Integration Testing (with auto-refinement)
            ├─ Deploy to ephemeral Elasticsearch (Docker)
            ├─ Ingest TP/FN/FP/TN test payloads
            ├─ Calculate precision/recall metrics
            └─ Smart decision: Fix QUERY or TEST CASES
                                        ↓
            STAGE 3: LLM Judge (with auto-refinement)
            ├─ Empirical evaluation (actual test results)
            ├─ Quality scoring (≥0.75 threshold)
            └─ Deployment decision: APPROVE/REFINE/REJECT
                                        ↓
            STAGE 3.5: TTP Intent Validation (optional)
            ├─ Validate test payload realism
            ├─ Check command syntax & TTP alignment
            └─ Research-backed recommendations
                                        ↓
                    Staging → Human Review → Production
```

## Prerequisites

- Python 3.11+ (3.12 or 3.13 recommended)
- GCP account with Vertex AI enabled (for Gemini API)
- GitHub account (for CI/CD)
- git CLI
- gh CLI (GitHub CLI)
- gcloud CLI ([installation guide](https://cloud.google.com/sdk/docs/install))
- Docker (for integration testing with Elasticsearch)

## Quick Setup

### Option 1: Automated Bootstrap (Recommended)

```bash
#clone and navigate to project
git clone https://github.com/dc401/adk-tide-generator.git
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

#note: region is auto-selected via round-robin rotation (no manual config needed)

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

#note: --location is optional; defaults to auto-selected region in CI/CD
#      or 'global' for local development
```

### With Self-Healing Refinement (Default)

```bash
#refinement enabled by default (max 3 iterations per rule)
python run_agent.py --cti-folder cti_src --output generated
```

### Disable Refinement (for testing)

```bash
python run_agent.py --cti-folder cti_src --output generated --no-refinement
```

### Quality-Driven Retry (Local Development with Elasticsearch)

Test-based refinement that automatically improves rules based on integration test results:

```bash
#start elasticsearch first (Docker)
docker run -d --name elasticsearch \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  -p 9200:9200 \
  docker.elastic.co/elasticsearch/elasticsearch:8.12.0

#run with quality retry (requires ES running)
python run_agent.py \
  --cti-folder cti_src \
  --output generated \
  --quality-retry \
  --max-iterations 3 \
  --precision-threshold 0.60 \
  --recall-threshold 0.70

#cleanup
docker stop elasticsearch && docker rm elasticsearch
```

**How it works:**
1. Generate rules from CTI
2. Run integration tests (TP/FN/FP/TN evaluation)
3. Check quality metrics (precision ≥60%, recall ≥70%)
4. If fail: Analyze failures and regenerate with feedback
5. Repeat up to max iterations (default: 3)

**Requirements:**
- Elasticsearch running locally on port 9200
- Docker (for ephemeral ES container)
- Designed for local development, not CI/CD

## End-to-End Testing

### Run Complete Pipeline (Recommended)

```bash
#test everything: generation → integration → TTP validation → summary
gh workflow run end-to-end-test.yml

#watch progress
gh run watch
```

See [END_TO_END_TEST.md](END_TO_END_TEST.md) for detailed usage and configuration options.

### Reuse Existing Rules

```bash
#skip generation, test existing artifacts
gh workflow run end-to-end-test.yml \
  -f skip_generation=true \
  -f existing_run_id=<RUN_ID>
```

### Quick Integration Test Only

```bash
#disable TTP validation for faster testing
gh workflow run end-to-end-test.yml \
  -f run_ttp_validator=false
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
- ECS field existence (1990 fields)
- ECS field research (3 attempts if invalid)
- YAML → JSON conversion
- LLM schema validation (research-backed)

Auto-refines up to 3 times per rule if failures occur.

### Stage 2: Integration Testing

```bash
python scripts/execute_detection_tests.py \
  --rules-dir generated/detection_rules \
  --es-url http://localhost:9200
```

Tests:
- Deploys rules to Elasticsearch (Docker container)
- Ingests TP/FN/FP/TN test payloads
- Calculates precision/recall/F1/accuracy
- Smart decision: Fix query OR test cases

Quality Thresholds:
- Precision ≥ 0.60 (max 40% false positives)
- Recall ≥ 0.70 (catch at least 70% of attacks)

### Stage 3: LLM Judge Evaluation

```bash
python scripts/run_llm_judge.py \
  --rules-dir generated/detection_rules \
  --test-results integration_test_results.yml \
  --project YOUR_GCP_PROJECT
```

Evaluates:
- Quality score based on actual test results (≥0.75 threshold)
- Deployment recommendation (APPROVE/REFINE/REJECT)
- Refines based on judge feedback if needed

### Stage 3.5: TTP Intent Validation

```bash
python scripts/test_ttp_validator.py generated/detection_rules
```

Validates:
- Command syntax realism (would it work in real attack?)
- TTP alignment (does payload match MITRE technique?)
- Field value realism (realistic log values?)
- Evasion technique validity (FN cases)

Outputs:
- Valid/invalid test case counts
- High/medium/low confidence scores
- Research-backed recommendations for invalid cases

## Multi-Level Refinement System

The system automatically refines rules at each failure stage:

### Validation Refinement
- **Trigger:** Lucene syntax errors, ECS field errors, schema violations
- **Fix:** Corrects operators, researches ECS fields, fixes MITRE references
- **Attempts:** Max 3 per rule

### Integration Test Refinement
- **Trigger:** Precision < 0.60 or Recall < 0.70
- **Smart Decision:** Analyzes if QUERY or TEST CASES need fixing
- **Fix:** Refines query logic OR updates test payloads
- **Attempts:** Max 2 per rule

### Judge Refinement
- **Trigger:** Deployment decision = REFINE
- **Fix:** Applies judge's specific recommendations
- **Attempts:** Max 2 per rule

See [docs/milestones/ITERATIVE_VALIDATION_SUCCESS.md](docs/milestones/ITERATIVE_VALIDATION_SUCCESS.md) for detailed documentation.

## Project Structure

```
adk-tide-generator/
├── detection_agent/               #core detection generation logic
│   ├── agent.py                   #main detection agent (5 stages)
│   ├── prompts/                   #LLM prompts (external files)
│   │   ├── detection_generator.md #rule generation with ECS research
│   │   ├── validator.md           #rule validation with research
│   │   ├── security_scan.md       #OWASP LLM Top 10 protection
│   │   └── ttp_validator_prompt.md #TTP intent validation guide
│   ├── schemas/                   #Pydantic schemas
│   │   ├── detection_rule.py      #ES Detection Rule schema
│   │   └── ecs_flat.yml           #1990 ECS fields
│   └── tools/                     #custom tools
│       ├── load_cti_files.py      #CTI file loader (PDF/DOCX/TXT/MD)
│       ├── validate_lucene.py     #Lucene syntax validator
│       ├── validate_ecs_fields.py #ECS field validator
│       ├── research_ecs_field.py  #ECS field research tool
│       ├── iterative_validator.py #3-attempt validation wrapper
│       └── ttp_intent_validator.py #TTP test payload validator
│
├── scripts/                       #validation and testing scripts
│   ├── bootstrap.sh               #interactive setup script
│   ├── validate_rules.py          #3-stage validation with refinement
│   ├── execute_detection_tests.py #ES integration testing
│   ├── integration_test_ci.py     #CI integration wrapper
│   ├── run_llm_judge.py           #empirical LLM judge with refinement
│   ├── test_ttp_validator.py      #TTP validator testing
│   ├── demo_ttp_validation.py     #TTP validator demonstration
│   ├── stage_passing_rules.py     #stage validated rules with UIDs
│   ├── create_review_pr.py        #automated PR creation
│   ├── deploy_local_demo.sh       #local deployment demo
│   ├── cleanup_staging.sh         #clean temp artifacts
│   ├── setup-gcp.sh               #GCP setup helper
│   └── setup-github-secrets.sh    #GitHub secrets helper
│
├── .github/workflows/             #CI/CD workflows
│   ├── end-to-end-test.yml        #master orchestration (6-12 min)
│   ├── generate-detections.yml    #rule generation (3-4 min)
│   ├── integration-test-simple.yml #integration testing (1-2 min)
│   ├── llm-judge.yml              #LLM quality evaluation
│   ├── mock-deploy.yml            #mock SIEM deployment
│   └── cleanup-stale-artifacts.yml #artifact cleanup
│
├── cti_src/                       #CTI input files
│   └── sample_cti.md              #example CTI file
│
├── generated/                     #agent outputs (gitignored)
│   ├── detection_rules/           #generated YAML rules
│   ├── cti_context.yml            #CTI analysis context
│   └── staging/                   #temp validation artifacts
│
├── production_rules/              #human-approved rules (deployed)
│   └── *.yml                      #production detection rules
│
├── archived_rules/                #deployment history
│   └── batch_*_deployed_*/        #audit trail with metadata
│
├── docs/                          #documentation
│   ├── milestones/                #important milestone documentation
│   │   ├── CORE_ECS_FIELD_FIX_SUCCESS.md
│   │   ├── ITERATIVE_VALIDATION_SUCCESS.md
│   │   ├── INTEGRATION_TEST_SUCCESS.md
│   │   ├── MOCK_DEPLOYMENT_SUCCESS.md
│   │   ├── STAGE_3_COMPLETE_PR_CREATED.md
│   │   └── TTP_VALIDATOR_IMPROVEMENT_CYCLE.md
│   └── archive/                   #session progress notes (historical)
│
├── run_agent.py                   #CLI entry point
├── requirements.txt               #Python dependencies
├── README.md                      #this file
├── END_TO_END_TEST.md             #end-to-end testing guide
├── SESSION_SUMMARY.md             #comprehensive session summary
├── BACKLOG.md                     #future improvements
├── TESTING_GUIDE.md               #testing documentation
└── ARCHITECTURE_ELASTICSEARCH_NATIVE.md #technical architecture
```

## GitHub Actions Workflows

### Workflow Orchestration

```
┌──────────────────────────────────────────────────────────────┐
│  END-TO-END TEST (Master Orchestration)                       │
│  .github/workflows/end-to-end-test.yml                        │
└──────────────────────────────────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│  GENERATE    │   │ INTEGRATION  │   │ TTP VALIDATE │
│  (reuses)    │   │   TEST       │   │ (optional)   │
│              │   │  (inline)    │   │  (inline)    │
│ generate-    │   │              │   │              │
│ detections   │   │ Downloads    │   │ Downloads    │
│ .yml via     │   │ artifacts    │   │ artifacts    │
│ workflow_    │   │              │   │              │
│ call         │   │ Starts       │   │ Runs TTP     │
│              │   │ Docker ES    │   │ validator    │
│ Uploads:     │   │              │   │              │
│ detection-   │   │ Uploads:     │   │ Uploads:     │
│ rules        │   │ test-results │   │ ttp-report   │
└──────────────┘   └──────────────┘   └──────────────┘
        │                  │                  │
        └──────────────────┼──────────────────┘
                           ▼
                   ┌──────────────┐
                   │   SUMMARY    │
                   │   (inline)   │
                   │              │
                   │ Downloads    │
                   │ all artifacts│
                   │              │
                   │ Generates    │
                   │ report       │
                   │              │
                   │ Uploads:     │
                   │ pipeline-    │
                   │ summary      │
                   └──────────────┘
```

### Workflow Descriptions

#### 1. End-to-End Test (Master Orchestration)
**File:** `.github/workflows/end-to-end-test.yml`
**Trigger:** Manual dispatch
**Runtime:** 6-12 minutes

**What it orchestrates:**
- Calls `generate-detections.yml` via `workflow_call` (reusable workflow)
- Runs integration test inline (to avoid circular dependencies)
- Runs TTP validation inline (optional)
- Aggregates all results into summary report

**Artifacts produced:**
- `detection-rules` (from generation)
- `integration-test-results` (test metrics)
- `ttp-validation-report` (test case validation)
- `pipeline-summary` (aggregated report)

**Usage:**
```bash
gh workflow run end-to-end-test.yml
gh workflow run end-to-end-test.yml -f skip_generation=true -f existing_run_id=123456
```

See [END_TO_END_TEST.md](END_TO_END_TEST.md) for detailed documentation.

---

#### 2. Generate Detection Rules
**File:** `.github/workflows/generate-detections.yml`
**Trigger:** Manual dispatch, workflow_call (from end-to-end-test), or push to main
**Runtime:** 3-5 minutes (15min timeout for multiple CTI files)

**When triggered:**
- **Manually:** `gh workflow run generate-detections.yml`
- **Automatically:** Push to main with changes in `cti_src/**`, `detection_agent/**`, or `run_agent.py`
- **From orchestration:** Called by `end-to-end-test.yml` via `workflow_call`

**Workflow steps:**
1. Clean stale artifacts
2. Install dependencies
3. Authenticate to GCP
4. Validate CTI files (security checks)
5. Run detection agent with iterative refinement
6. Verify rule generation
7. Upload `detection-rules` artifact

---

#### 3. Integration Test - Elasticsearch
**File:** `.github/workflows/integration-test-simple.yml`
**Trigger:** Manual dispatch with `artifact_run_id` parameter
**Runtime:** 1-2 minutes

**Purpose:** Standalone integration testing (can be run independently)

**Usage:**
```bash
gh workflow run integration-test-simple.yml -f artifact_run_id=<RUN_ID>
```

**What it does:**
- Downloads `detection-rules` artifact from specified run
- Starts ephemeral Elasticsearch 8.12.0 (Docker)
- Deploys rules and ingests test payloads
- Calculates precision, recall, F1, accuracy
- Uploads `integration-test-results` artifact

**Note:** The end-to-end test runs this logic inline instead of calling this workflow to avoid dependency issues.

---

#### 4. Mock SIEM Deployment
**File:** `.github/workflows/mock-deploy.yml`
**Trigger:** PR merge to main (with staged rules)
**Runtime:** 2-3 minutes

**Purpose:** Demonstrates production deployment after human review.

**Workflow:**
1. PR created with staged rules → human review
2. PR approved and merged → triggers this workflow
3. Deploys to ephemeral Elasticsearch (mock production)
4. Moves approved rules to `production_rules/`
5. Archives deployment with audit trail

---

#### 5. Cleanup Stale Artifacts
**File:** `.github/workflows/cleanup-stale-artifacts.yml`
**Trigger:** Weekly schedule (Sunday 2AM UTC) or manual dispatch
**Runtime:** <1 minute

**Purpose:** Prevents artifact clutter and quota issues.

**What it cleans:**
- Generated artifacts not linked to open PRs
- Session results (temporary execution logs)
- Staging directories

**Protected:**
- `production_rules/` (human-approved rules)
- Files linked to open PRs
- Artifacts from recent workflow runs

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
- Max 50 files per run (DoS prevention)

### Output Sanitization
- Removes injection patterns from generated rules
- Validates Lucene syntax before writing
- ECS field validation with research grounding
- Schema validation with research

## Cost Optimization

### Model Selection
- **Gemini 2.5 Flash:** Rule generation (fast, cheap, $0.000075/1K input tokens)
- **Gemini 2.5 Pro:** Validation, judging, TTP validation (accurate, $0.00125/1K input tokens)

### Quota Management
- Inter-agent delay: 3.0s
- Aggressive retry backoff
- Session-level retry with exponential backoff
- Max 3 validation iterations per rule
- Max 2 integration test iterations per rule
- Max 2 judge iterations per rule

### Token Efficiency
- External prompts (no inline repetition)
- Truncated outputs (120k char limit)
- State pruning between stages
- Field research caching

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
#test with Docker Elasticsearch
docker run -d --name elasticsearch \
  -p 9200:9200 \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  docker.elastic.co/elasticsearch/elasticsearch:8.12.0

python scripts/execute_detection_tests.py \
  --rules-dir generated/detection_rules \
  --es-url http://localhost:9200
```

### End-to-End Test (GitHub Actions)
```bash
#complete pipeline
gh workflow run end-to-end-test.yml

#watch progress
gh run watch

#download results
gh run download <RUN_ID>
```

### TTP Validator Test
```bash
#validate test payloads for production rules
export GOOGLE_CLOUD_PROJECT=$(gcloud config get-value project)
python scripts/test_ttp_validator.py production_rules/
```

## Troubleshooting

### GCP Authentication Errors
```bash
#re-authenticate
gcloud auth application-default login

#verify project
gcloud config get-value project

#set project if not configured
export GOOGLE_CLOUD_PROJECT="your-project-id"

#note: region auto-selected via round-robin (no GOOGLE_CLOUD_LOCATION needed)
```

### Quota Exhaustion

**Note:** The system now automatically rotates through 8 regions to avoid quota exhaustion. If you still hit quota limits:

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

#check session results
cat session_results/detection_session_*.json | jq .
```

### Integration Test Failures
```bash
#check Elasticsearch status
curl http://localhost:9200/_cluster/health

#manually restart Docker container
docker restart elasticsearch

#check Elasticsearch logs
docker logs elasticsearch

#check version compatibility (must be 8.12.0)
grep "elasticsearch==" requirements.txt
```

### Elasticsearch Version Mismatch
```bash
#symptom: "Accept version must be either version 8 or 7, but found 9"
#fix: ensure requirements.txt has correct versions
elasticsearch==8.12.0
elastic-transport==8.15.1
```

### TTP Validation Errors
```bash
#check GCP authentication
gcloud auth application-default login

#verify project is set
echo $GOOGLE_CLOUD_PROJECT

#run with explicit project
python scripts/test_ttp_validator.py \
  --project YOUR_PROJECT_ID \
  generated/detection_rules/
```

## Documentation

### Essential
- [README.md](README.md) - This file
- [END_TO_END_TEST.md](END_TO_END_TEST.md) - End-to-end testing guide
- [SESSION_SUMMARY.md](SESSION_SUMMARY.md) - Comprehensive session summary
- [BACKLOG.md](BACKLOG.md) - Future improvements roadmap
- [TESTING_GUIDE.md](TESTING_GUIDE.md) - Testing procedures
- [ARCHITECTURE_ELASTICSEARCH_NATIVE.md](ARCHITECTURE_ELASTICSEARCH_NATIVE.md) - Technical architecture

### Milestones
- [docs/milestones/CORE_ECS_FIELD_FIX_SUCCESS.md](docs/milestones/CORE_ECS_FIELD_FIX_SUCCESS.md) - ECS field fix milestone
- [docs/milestones/ITERATIVE_VALIDATION_SUCCESS.md](docs/milestones/ITERATIVE_VALIDATION_SUCCESS.md) - Iterative validation system
- [docs/milestones/INTEGRATION_TEST_SUCCESS.md](docs/milestones/INTEGRATION_TEST_SUCCESS.md) - Integration testing milestone
- [docs/milestones/MOCK_DEPLOYMENT_SUCCESS.md](docs/milestones/MOCK_DEPLOYMENT_SUCCESS.md) - Mock deployment milestone
- [docs/milestones/STAGE_3_COMPLETE_PR_CREATED.md](docs/milestones/STAGE_3_COMPLETE_PR_CREATED.md) - Human-in-the-loop workflow
- [docs/milestones/TTP_VALIDATOR_IMPROVEMENT_CYCLE.md](docs/milestones/TTP_VALIDATOR_IMPROVEMENT_CYCLE.md) - TTP validator demonstration

## Quality Metrics

### Current Production Rules
- **Rules Deployed:** 3 (Akira ransomware detection set)
- **LLM Quality Scores:** 0.93-0.97 (all pass ≥0.75 threshold)
- **Integration Test Precision:** 45.5%
- **Integration Test Recall:** 62.5%
- **TTP Validation Pass Rate:** 88% (15/17 valid initial, 100% after fixes)

### Target Metrics
- **Precision:** ≥ 0.60 (max 40% false positives)
- **Recall:** ≥ 0.70 (catch at least 70% of attacks)
- **LLM Quality Score:** ≥ 0.75
- **TTP Validation:** 100% valid test cases

See [BACKLOG.md](BACKLOG.md) for planned quality improvements.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly:
   - Unit tests
   - Integration tests
   - End-to-end workflow test
5. Update documentation
6. Submit a pull request

## License

MIT License - See LICENSE file for details

## Support

For issues and questions:
- GitHub Issues: https://github.com/dc401/adk-tide-generator/issues
- Documentation: See docs/ folder
- Session Summary: [SESSION_SUMMARY.md](SESSION_SUMMARY.md)

## Acknowledgments

Built with:
- Google Gemini 2.5 (Flash & Pro) via Vertex AI
- Elasticsearch Detection Rule API (8.12.0)
- ECS (Elastic Common Schema) 8.11
- luqum (Lucene query parser)
- Pydantic (schema validation)
- GitHub Actions (CI/CD)
- Docker (ephemeral testing infrastructure)
