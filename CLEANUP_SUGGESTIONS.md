# Code Simplification & Cleanup Suggestions

Generated: 2026-02-09

## Files That May Be Redundant

### 1. .env.example
**Current State:** Contains outdated guidance (references GOOGLE_APPLICATION_CREDENTIALS which bootstrap.sh says NOT to set)  
**Actual Usage:** bootstrap.sh auto-creates .env file with correct settings  
**References:** setup-gcp.sh, validate-setup.sh  
**Recommendation:**  
- Option A: Update .env.example to match what bootstrap.sh creates
- Option B: Remove .env.example since bootstrap.sh auto-generates it
- **Suggested Action:** Update with warning that bootstrap.sh auto-creates it

### 2. Setup Scripts (Potentially Superseded by bootstrap.sh)
**Files:**
- `scripts/setup-gcp.sh` (7KB) - GCP project setup
- `scripts/validate-setup.sh` (6KB) - Validation checks
- `scripts/setup-github-secrets.sh` (2KB) - GitHub secrets setup

**Current State:** bootstrap.sh (21KB) appears to include all their functionality  
**Recommendation:**  
- Option A: Keep for granular manual setup
- Option B: Move to archive/ folder
- **Suggested Action:** Keep for now (users may want granular control)

### 3. Test/Demo Scripts
**Files:**
- `scripts/test_agent_components.py` (dev testing, not used in workflows)
- `scripts/demo_ttp_validation.py` (demo script, not used in workflows)

**Recommendation:**  
- Option A: Move to scripts/dev/ folder for development use
- Option B: Keep in scripts/ but add comment that they're dev-only
- **Suggested Action:** Add header comments marking as dev/debugging tools

### 4. Archived Workflow
**File:** `.github/workflows/archive/llm-judge.yml`  
**Status:** Single archived workflow  
**Recommendation:** Keep archive folder for historical reference

### 5. Validation Scripts (Different Purposes, All Active)
**Files:**
- `scripts/validate_rules.py` (469 lines) - Pre-integration pipeline
- `scripts/validate_detection_rules.py` (165 lines) - Quick validation without ES
- `scripts/validate_local.py` (171 lines) - Local validation without GCP

**Recommendation:** Keep all three - they serve different use cases

### 6. Staging Scripts (Different Purposes, Both Active)
**Files:**
- `scripts/stage_approved_rules.py` (104 lines) - Used in archived workflow
- `scripts/stage_passing_rules.py` (237 lines) - Active

**Recommendation:**  
- Move stage_approved_rules.py to archive/ since it's only used in archived workflow
- **Suggested Action:** Move to scripts/archive/

## Code Quality Improvements

### 1. Consistent Logging
**Current:** Mix of print statements with different formats  
**Suggestion:** Consider a logging module for consistency (low priority)

### 2. Error Handling in quality_retry.py
**Current:** Generic try/except with empty stderr message  
**Improvement:** Add more specific error types and messages (already improved with ES check)

### 3. Duplicate Imports
**Issue:** Some modules import `time` in loops  
**Fix:** Move imports to top of file  
**Status:** ✅ Fixed in quality_retry.py and refinement.py

## Configuration Simplification

### 1. Hard-coded Timeouts
**Current:** Timeouts scattered across agent.py and quality_retry.py  
**Suggestion:** Centralize timeout configs in a config.py or constants  
**Priority:** Low (current approach is clear and self-documenting)

### 2. Quality Thresholds
**Current:** Default thresholds in multiple places (quality_retry.py, run_agent.py)  
**Suggestion:** Single source of truth for defaults  
**Priority:** Low (CLI args allow override anyway)

## Dependencies Review

No unnecessary dependencies found in requirements.txt. All packages are actively used:
- google-adk: Core framework ✓
- google-genai: Gemini API ✓
- pydantic: Schema validation ✓
- elasticsearch: Integration testing ✓
- PyYAML: Rule I/O ✓
- python-dotenv: .env loading ✓
- All other dependencies are actively used

## Summary

**High Priority:**
1. ✅ Remove unused imports (DONE)
2. ✅ Add ES availability check in quality_retry (DONE)
3. ✅ Enhance refinement logging (DONE)
4. Update .env.example with current best practices
5. Move stage_approved_rules.py to archive/

**Low Priority (Keep As-Is):**
1. Multiple validation scripts (serve different purposes)
2. Setup scripts (useful for granular control)
3. Test/demo scripts (useful for development)

**Not Recommended:**
1. Consolidating validation scripts (lose flexibility)
2. Removing bootstrap.sh in favor of manual setup (worse UX)
3. Centralizing all configs (reduces code clarity)
