# Detection Quality Analysis - 2026-02-09

## Problem Identification

### Test Results Before Prompt Enhancement

**Run ID:** 21812959403 (completed 05:09 UTC)

**Overall Metrics:**
- Precision: 45.5% (Target: ≥60%) ❌
- Recall: 25.0% (Target: ≥70%) ❌
- F1 Score: 0.323
- Accuracy: 55.3%

### Per-Rule Breakdown

**Failing GCP Rules (0% detection):**
1. `gcp_compute_instance_os_password_reset` - 0% P / 0% R
2. `gcp_compute_instance_startup_script_modification` - 0% P / 0% R
3. `gcp_firewall_rule_modification` - 0% P / 0% R
4. `gcp_new_compute_instance_creation` - 0% P / 0% R
5. `gcp_compute_snapshot_deletion` - 0% P / 0% R
6. `gcp_ssh_key_addition_to_instance_metadata` - 0% P / 0% R

**Working Windows Rules (partial success):**
1. `windows_ransom_note_file_creation` - 40% P / 100% R (too many FPs)
2. `windows_service_stop_or_disable_via_cli` - 50% P / 100% R (too many FPs)

**Failing Windows Rule:**
1. `windows_shadow_copy_deletion_via_cli` - 0% P / 0% R

## Root Cause Analysis

### Issue #1: GCP Queries Too Generic

**Problem Query Example:**
```lucene
event.kind:event AND event.category:cloud AND cloud.provider:gcp AND event.dataset:google_cloud.audit
```

**Issues:**
1. Uses `event.category:cloud` instead of `event.category:api` (GCP audit logs are API calls)
2. Missing specific `event.action` field (e.g., `google.compute.v1.Snapshots.Delete`)
3. Only matches dataset (equivalent to matching ALL GCP audit logs)
4. Results in 0% detection because field values don't match Elasticsearch schema

**Why This Happens:**
- Prompt didn't explicitly require `event.category:api` for GCP
- Prompt didn't emphasize the critical importance of `event.action` specificity
- No examples of correct GCP queries vs incorrect ones

### Issue #2: Windows Queries Too Broad

**Example: Service Stop Rule**
- 50% precision (too many false positives)
- Matching on `process.name:(*net* OR *sc*)` is too broad
- Needs more specific command-line filtering

### Issue #3: Shadow Copy Rule Not Matching

**Problem:**
- 0% recall suggests syntax error or field mismatch
- Needs investigation of actual test payload structure

## Solution Implemented

### Prompt Enhancement: `detection_generator.md`

**Added Section 1: GCP Audit Log Detections (Lines 237-270)**

```markdown
### GCP Audit Log Detections (CRITICAL)

**GCP detection queries MUST be SPECIFIC - avoid overly broad matches:**

**REQUIRED fields for GCP audit logs:**
- `cloud.provider:gcp` - Filter to GCP events only
- `event.category:api` - GCP audit logs are API calls (NOT "cloud")
- `event.action:google.*` - SPECIFIC API method
- `event.outcome:success` (or `failure`) - Filter by result

**Common GCP field patterns:**
CORRECT: cloud.provider:gcp AND event.category:api AND event.action:google.compute.v1.Snapshots.Delete

WRONG: cloud.provider:gcp AND event.category:cloud AND gcp.audit.service.name:compute.googleapis.com
```

**Added Section 2: False Positive Prevention (Lines 272-299)**

```markdown
### False Positive Prevention

**Common false positive causes:**
1. Missing action specificity
2. Missing outcome filtering
3. Too broad process matching
4. Missing event lifecycle
```

## Expected Improvements

### After Prompt Enhancement

**GCP Rules:**
- Should use `event.category:api` instead of `event.category:cloud`
- Should include specific `event.action:google.{service}.{version}.{Resource}.{Action}`
- Should filter by `event.outcome:success`
- Expected: 60-80% precision, 70-90% recall (from 0%)

**Windows Rules:**
- Should have more specific command-line patterns
- Should filter out benign administrative operations
- Expected: 60-80% precision (from 40-50%)

## Testing Plan

**New Test Triggered:** Workflow run with enhanced prompt

**Monitoring:**
1. Check if GCP rules use `event.category:api` ✓
2. Check if GCP rules have specific `event.action` ✓
3. Check if precision improves above 60%
4. Check if recall improves above 70%
5. Check if any rules pass LLM judge (≥0.75 score)
6. Check if PR is created for human review

## Metrics to Watch

**Quality Gates:**
- Precision threshold: ≥60%
- Recall threshold: ≥70%
- LLM judge score: ≥0.75
- F1 score: (calculated from P/R)

**Success Criteria for PR Creation:**
- At least 1 rule must meet all quality thresholds
- Rule must pass integration tests
- Rule must pass LLM judge evaluation
- Rule must pass TTP intent validation

## Next Steps

1. **Wait for new test to complete** (~ 15-20 minutes)
2. **Analyze new results** - Compare before/after metrics
3. **If still failing:**
   - Investigate specific query issues
   - Check test payload structure
   - Consider per-rule refinement
4. **If passing:**
   - Verify PR is created
   - Review staged rules
   - Document success patterns

## Commit History

- `5840eda` - Enhanced detection prompt with GCP specificity and FP prevention
- `31f9363` - Added progress summary and cleanup documentation
- `02d9da5` - Code cleanup and simplification
- `17fc3b1` - Enhanced refinement logging with timing and phase details
- `b899d58` - Fixed quality retry ES availability check
- `7a2f48c` - Added quality-driven retry loop
- `a771f26` - Removed unused imports

## Status

**Current:** Waiting for end-to-end test with improved prompt (triggered 01:10 UTC)

**Expected Completion:** ~01:25-01:30 UTC

**Next Action:** Analyze results and determine if additional refinements needed
