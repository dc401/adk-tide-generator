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

## Test Results After Dynamic Prompt Fix

**Run ID:** 21822584073 (completed 11:14 UTC)

**Overall Metrics:**
- Precision: 37.5% (Target: ≥60%) ❌ (WORSE than before)
- Recall: 60.0% (Target: ≥70%) ❌ (slightly worse)
- F1 Score: 0.462
- Accuracy: 41.7%

### Per-Rule Breakdown

**GCP Rules - Now Working (Dynamic Prompt Fixed These):**
1. `gcp_firewall_rule_modification` - 40% P / 100% R ✅
2. `gcp_new_compute_instance_creation` - 40% P / 100% R ✅
3. `gcp_compute_snapshot_deletion` - 40% P / 100% R ✅
4. `gcp_-_instance_ssh_key_modification` - 25% P / 50% R (partial)
5. `gcp_-_instance_startup_script_modification` - 0% P / 0% R (field mismatch)

**Windows Rules - Still Broken:**
1. `akira_-_windows_shadow_copy_deletion` - 0% P / 0% R ❌ (all 3 TP tests failed)
2. `akira_-_windows_service_stop_or_disable` - No test cases generated ❌
3. `akira_-_ransom_note_file_creation` - 40% P / 100% R (high FP rate)

## Root Cause: Test Payload Generation Issues

### Issue #1: Windows Shadow Copy Rule Not Matching

**Query (looks correct):**
```lucene
event.category:process AND event.type:start AND
(process.name:(*vssadmin*) AND process.command_line:(*delete*shadows*))
```

**Test Results:**
- TP test 1: "Malicious vssadmin shadow deletion" - Expected match, DIDN'T MATCH (FN)
- TP test 2: "Malicious wmic shadowcopy deletion" - Expected match, DIDN'T MATCH (FN)
- TP test 3: "Malicious bcdedit recovery disable" - Expected match, DIDN'T MATCH (FN)

**Hypothesis:** Test payload structure doesn't match query expectations (field names or values)

### Issue #2: Windows Service Stop Rule Has No Tests

**Rule:** `akira_-_windows_service_stop_or_disable`
**Results:** All metrics 0, "details": []
**Problem:** Test generation agent failed to create ANY test payloads for this rule

### Issue #3: GCP Rules High False Positive Rate

**Pattern:** All GCP rules have 3 FPs out of 5 tests (60% FP rate)
**Example:** TN test "Normal GCP instance listing API call" triggers firewall/snapshot rules
**Problem:** Test payloads have wrong event.action values OR queries too broad

## Diagnosis Plan

1. **Check Windows test payloads** - Verify field structure matches ECS
2. **Check test generation** - Why did service stop rule get 0 tests?
3. **Check GCP TN/FP payloads** - Do they have correct event.action values?

## Test Results After Index Mapping Fix

**Run ID:** 21822965084 (completed 11:27 UTC)

**Overall Metrics:**
- Precision: 43.2% (Target: ≥60%) ❌ (improved from 37.5%)
- Recall: 80.0% (Target: ≥70%) ✅✅ (MAJOR improvement from 60%)
- F1 Score: 0.561 (improved from 0.462)
- Accuracy: 46.8%

### BREAKTHROUGH: Windows Rules Now Working!

**Index Mapping Fix Resolved Field Type Issues:**

**Windows Rules - ALL NOW DETECTING:**
1. `akira_ransomware_-_shadow_copy_deletion` - 50% P / 100% R ✅✅ (was 0%)
   - ALL 3 TP tests now match (vssadmin, wmic, bcdedit)
   - Fixed by mapping process.name/command_line as "wildcard" type
2. `akira_ransomware_-_service_stop_via_cli` - 50% P / 100% R ✅✅ (tests generated now)
3. `akira_ransomware_-_ransom_note_creation` - 40% P / 100% R ✅

**GCP Rules - Still Working:**
1. `gcp_firewall_rule_modification` - 40% P / 100% R ✅
2. `gcp_new_compute_instance_launch` - 40% P / 100% R ✅
3. `gcp_os_windows_password_reset` - 40% P / 100% R ✅
4. `gcp_compute_snapshot_deletion` - 40% P / 100% R ✅
5. `gcp_compute_startup_script_modification` - 0% P / 0% R ❌ (nested field issue)
6. `gcp_ssh_backdoor_creation_via_metadata` - 0% P / 0% R ❌ (nested field issue)

## Remaining Issue: Test Payload Quality (Low Precision)

**Pattern:** ALL working rules have 40-50% precision due to TN/FP test payloads incorrectly matching

**Examples:**
- TN test "Normal system activity" triggers shadow copy rule (should NOT match)
- TN test "Normal GCP API call (storage bucket creation)" triggers firewall rule (should NOT match)
- FP test "Legitimate admin deleting snapshot" triggers snapshot deletion rule (should NOT match)

**Root Cause:** Test payloads for TN/FP cases don't properly differentiate from TP cases

**Solutions to Consider:**
1. Improve test payload generation prompt to create more realistic benign payloads
2. Add more specific exclusion filters to detection queries
3. Enhance FP test cases with correct event.action values for benign operations

## Status

**Current:** Recall threshold MET (80% ≥ 70%) ✅ | Precision still needs improvement (43.2% < 60%)

**Major Win:** Index mapping fix resolved Windows rule matching - recall jumped 20%!

**Next Action:** Improve test payload generation or refine queries to reduce false positives
