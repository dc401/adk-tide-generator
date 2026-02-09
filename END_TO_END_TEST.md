# End-to-End Detection Pipeline Testing

## Overview

The **End-to-End Detection Pipeline Test** is a master orchestration workflow that automates the complete detection engineering pipeline in a single run.

## Pipeline Flow

```
CTI Files → Generate Detection Rules → Integration Test (Docker ELK) → TTP Validation → Summary Report
```

## Workflow File

`.github/workflows/end-to-end-test.yml`

## Usage

### Basic Usage (Full Pipeline)

Run the complete pipeline from scratch:

```bash
gh workflow run end-to-end-test.yml
```

This will:
1. Generate detection rules from CTI sources
2. Run integration tests with ephemeral Elasticsearch
3. Validate test payloads with TTP Intent Validator
4. Generate comprehensive summary report

### Advanced Usage

#### Skip Generation (Use Existing Rules)

If you want to test existing detection rules without regenerating them:

```bash
gh workflow run end-to-end-test.yml \
  -f skip_generation=true \
  -f existing_run_id=<RUN_ID>
```

Example:
```bash
gh workflow run end-to-end-test.yml \
  -f skip_generation=true \
  -f existing_run_id=21810501531
```

#### Disable TTP Validation

To run only generation + integration testing (skip TTP validation):

```bash
gh workflow run end-to-end-test.yml \
  -f run_ttp_validator=false
```

#### Combined Options

```bash
gh workflow run end-to-end-test.yml \
  -f skip_generation=true \
  -f existing_run_id=21810501531 \
  -f run_ttp_validator=false
```

## Workflow Inputs

| Input | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `skip_generation` | boolean | No | false | Skip rule generation, use existing artifacts |
| `existing_run_id` | string | No | - | Run ID with detection-rules artifact (required if skip_generation=true) |
| `run_ttp_validator` | boolean | No | true | Run TTP Intent Validator after integration test |

## Pipeline Stages

### Stage 1: Generate Detection Rules

**Job:** `generate`
**Duration:** ~3-5 minutes
**Output:** `detection-rules` artifact

**What it does:**
- Loads CTI files from `cti_src/`
- Runs ADK agent to generate Elasticsearch detection rules
- Validates YAML syntax
- Uploads detection rules as workflow artifact

**Skip condition:** Set `skip_generation=true` to skip this stage

---

### Stage 2: Integration Testing

**Job:** `integration-test`
**Duration:** ~1-2 minutes
**Output:** `integration-test-results` artifact

**What it does:**
- Downloads detection rules from Stage 1 (or from `existing_run_id`)
- Starts ephemeral Elasticsearch 8.12.0 container
- Executes detection tests with test payloads (TP/FN/FP/TN)
- Calculates metrics: Precision, Recall, F1 Score, Accuracy
- Checks quality thresholds:
  - **Precision ≥ 0.60** (max 40% false positives)
  - **Recall ≥ 0.70** (catch at least 70% of attacks)
- Tears down Elasticsearch container

**Outputs:**
- `test_passed`: true/false (whether quality thresholds met)
- `precision`: 0.0-1.0
- `recall`: 0.0-1.0
- `f1_score`: 0.0-1.0

---

### Stage 3: TTP Intent Validation

**Job:** `ttp-validation`
**Duration:** ~2-5 minutes
**Output:** `ttp-validation-report` artifact

**What it does:**
- Downloads detection rules
- Runs Gemini 2.5 Pro-based TTP validator on all test payloads
- Validates:
  - Command syntax realism (would it work in real attack?)
  - TTP alignment (does payload match MITRE technique?)
  - Field value realism (realistic log values?)
  - Evasion technique validity (FN cases)
- Outputs validation report with valid/invalid counts

**Outputs:**
- `validation_passed`: true/false (all test cases valid)
- `valid_count`: Number of valid test cases
- `invalid_count`: Number of invalid test cases

**Skip condition:** Set `run_ttp_validator=false` to skip this stage

---

### Stage 4: Summary Report

**Job:** `summary`
**Duration:** ~30 seconds
**Output:** `pipeline-summary` artifact + GitHub Job Summary

**What it does:**
- Aggregates results from all stages
- Generates markdown summary report
- Displays overall pipeline status:
  - ✅ **PASS**: All stages successful, quality thresholds met
  - ⚠️ **WARN**: Tests completed but quality below thresholds
  - ❌ **FAIL**: Critical stage failed (generation or integration test)
- Uploads summary as artifact
- Adds summary to GitHub Actions job summary UI

---

## Quality Thresholds

### Integration Test Thresholds

- **Precision ≥ 0.60** (60%)
  - Maximum 40% false positive rate
  - Rules should not trigger on too much benign activity

- **Recall ≥ 0.70** (70%)
  - Catch at least 70% of malicious activity
  - Rules should detect most real attacks

**Result:**
- If both thresholds met: `test_passed = true`
- If either threshold missed: `test_passed = false` (pipeline warns but doesn't fail)

### TTP Validation Threshold

- **100% valid test cases required** for `validation_passed = true`
- If any test cases are invalid: `validation_passed = false`

**Result:**
- Pipeline warns but doesn't fail if TTP validation fails
- Allows manual review of invalid test cases

---

## Pipeline Status Codes

| Status | Icon | Meaning | Action |
|--------|------|---------|--------|
| **PASS** | ✅ | All stages successful, quality met | Ready for production review |
| **WARN** | ⚠️ | Tests ran but quality below threshold | Review metrics, improve rules |
| **FAIL** | ❌ | Critical stage failed | Check logs, fix errors |

---

## Artifacts

All artifacts are retained for **30 days**.

| Artifact Name | Created By | Contents |
|---------------|------------|----------|
| `detection-rules` | generate | Generated Elasticsearch detection rules (YAML) + CTI context |
| `integration-test-results` | integration-test | test_results.json with TP/FN/FP/TN metrics |
| `ttp-validation-report` | ttp-validation | Text report with validation results |
| `pipeline-summary` | summary | Markdown report with overall pipeline status |

### Download Artifacts

**Via GitHub UI:**
1. Go to Actions tab
2. Click on workflow run
3. Scroll to "Artifacts" section
4. Click artifact name to download

**Via CLI:**
```bash
#list artifacts for a run
gh run view <RUN_ID> --log-failed

#download specific artifact
gh run download <RUN_ID> -n detection-rules

#download all artifacts
gh run download <RUN_ID>
```

---

## Monitoring Workflow Progress

### Watch Live

```bash
gh run watch
```

### View Logs

```bash
#all jobs
gh run view <RUN_ID> --log

#specific job
gh run view <RUN_ID> --job=<JOB_ID> --log
```

### Check Status

```bash
gh run list --workflow=end-to-end-test.yml --limit 5
```

---

## Example Workflows

### Test New CTI File

1. Add new CTI file to `cti_src/`:
   ```bash
   cp ~/Downloads/threat-report.pdf cti_src/
   git add cti_src/threat-report.pdf
   git commit -m "Add new threat intel report"
   git push
   ```

2. Run end-to-end test:
   ```bash
   gh workflow run end-to-end-test.yml
   ```

3. Monitor progress:
   ```bash
   gh run watch
   ```

4. Download results when complete:
   ```bash
   gh run download <RUN_ID>
   ```

### Re-test Existing Rules

If integration tests failed due to infrastructure issues (not rule quality), re-test without regenerating:

```bash
#find previous successful generation run
gh run list --workflow=generate-detections.yml --limit 1 --json databaseId,conclusion \
  --jq '.[] | select(.conclusion=="success") | .databaseId'

#use that run ID for testing
gh workflow run end-to-end-test.yml \
  -f skip_generation=true \
  -f existing_run_id=<RUN_ID>
```

### Quick Integration Test Only

Skip both generation (use existing) and TTP validation:

```bash
gh workflow run end-to-end-test.yml \
  -f skip_generation=true \
  -f existing_run_id=<RUN_ID> \
  -f run_ttp_validator=false
```

---

## Troubleshooting

### Generation Stage Fails

**Symptoms:** `generate` job fails

**Common Causes:**
- No CTI files in `cti_src/`
- CTI files too large (>50MB)
- GCP authentication failure
- Gemini API quota exhausted

**Solutions:**
- Check CTI files exist and are valid formats (PDF, TXT, MD, DOCX)
- Verify GCP secrets configured: `GCP_SA_KEY`, `GCP_PROJECT_ID`, `GOOGLE_CLOUD_LOCATION`
- Check Gemini API quota in GCP console
- Review generation logs: `gh run view <RUN_ID> --job=generate --log`

---

### Integration Test Stage Fails

**Symptoms:** `integration-test` job fails

**Common Causes:**
- Elasticsearch container failed to start
- No rules to test (artifact download failed)
- Test execution script error
- Elasticsearch version mismatch

**Solutions:**
- Check Docker service is running in GitHub runner
- Verify `elasticsearch:8.12.0` image is accessible
- Check `requirements.txt` has elasticsearch==8.12.0 (not 9.x)
- Review integration test logs: `gh run view <RUN_ID> --job=integration-test --log`

---

### TTP Validation Stage Fails

**Symptoms:** `ttp-validation` job fails

**Common Causes:**
- GCP authentication failure
- Gemini API quota exhausted
- Invalid YAML in detection rules
- Test payloads missing from rules

**Solutions:**
- Verify GCP secrets configured
- Check Gemini API quota (Gemini 2.5 Pro has lower limits)
- Validate detection rule YAML syntax
- Ensure test_cases embedded in rule YAML files
- Review validation logs: `gh run view <RUN_ID> --job=ttp-validation --log`

---

### PR Creation Stage Fails

**Symptoms:** `auto-create-pr` job fails with:
```
GitHub Actions is not permitted to create or approve pull requests
```

**Cause:** Repository workflow permissions not configured

**Solutions:**
1. Go to **Settings → Actions → General** in your repository
2. Scroll to **Workflow permissions**
3. Enable: **"Allow GitHub Actions to create and approve pull requests"**
4. Click **Save**
5. Re-run the failed workflow job

**Note:** This is a one-time configuration. After enabling, all future workflows will be able to auto-create PRs.

**Alternative:** If you prefer not to enable auto-PR creation:
- Manually create PR from the generated branch (check workflow logs for branch name)
- Detection rules are already committed and ready for review
- Only the PR creation step failed, all detection work succeeded

---

### Quality Thresholds Not Met

**Symptoms:** Pipeline completes but shows ⚠️ WARN status

**Solutions:**

**Low Precision (<0.60):**
- Too many false positives
- Review FP test cases in `test_results.json`
- Tighten detection logic (add more specific filters)
- Add filter_legitimate sections to Sigma rules

**Low Recall (<0.70):**
- Missing too many attacks
- Review FN test cases in `test_results.json`
- Broaden detection logic (cover more attack variations)
- Check if evasion techniques in FN tests are realistic

**Invalid TTP Test Cases:**
- Review `ttp-validation-report` artifact
- Check validator feedback for each invalid test case
- Update test payloads based on recommendations
- Re-run pipeline after fixes

---

## Performance

**Typical Runtime:**
- Full pipeline (all stages): **6-12 minutes**
  - Generation: 3-5 min
  - Integration test: 1-2 min
  - TTP validation: 2-5 min
  - Summary: 30 sec

**With skip_generation=true:** **3-7 minutes**
  - Integration test: 1-2 min
  - TTP validation: 2-5 min
  - Summary: 30 sec

**With run_ttp_validator=false:** **4-7 minutes**
  - Generation: 3-5 min
  - Integration test: 1-2 min
  - Summary: 30 sec

---

## GitHub Actions Quotas

**Free Tier:**
- 2,000 minutes/month
- ~166 full pipeline runs/month
- ~330 runs with skip_generation=true

**Pro Tier:**
- 3,000 minutes/month
- ~250 full pipeline runs/month
- ~500 runs with skip_generation=true

**Recommendation:** Use `skip_generation=true` when testing fixes to integration tests or TTP validation to conserve quota.

---

## Integration with Other Workflows

### Trigger After Push

The end-to-end test workflow can be automatically triggered after pushes to main:

```yaml
#add to end-to-end-test.yml on: section
on:
  workflow_dispatch:
    # ... existing inputs ...
  push:
    branches: [main]
    paths:
      - 'cti_src/**'
      - 'detection_agent/**'
```

**Warning:** This will consume quota quickly. Recommend manual triggering for development.

### Scheduled Testing

Run end-to-end tests weekly to catch regressions:

```yaml
#add to end-to-end-test.yml on: section
on:
  workflow_dispatch:
    # ... existing inputs ...
  schedule:
    - cron: '0 0 * * 0'  #every Sunday at midnight UTC
```

---

## Summary

The end-to-end test workflow provides a single command to validate the entire detection engineering pipeline:

✅ **Generation** → ✅ **Integration Testing** → ✅ **TTP Validation** → 📊 **Summary Report**

Use it to:
- Test new CTI sources
- Validate detection rule quality
- Catch regressions in pipeline
- Generate quality reports for review

**Quick Start:**
```bash
gh workflow run end-to-end-test.yml
gh run watch
```
