#!/bin/bash
#test_core.sh - progressive testing of core functionality

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "================================"
echo "Core Functionality Testing"
echo "================================"
echo ""

#detect python command
if command -v python3 &> /dev/null; then
    PY="python3"
elif command -v python &> /dev/null; then
    PY="python"
else
    echo -e "${RED}✗ Python not found${NC}"
    exit 1
fi

#test 1: python environment
echo -e "${YELLOW}[1/7] Python Environment${NC}"
echo "  ✓ Python: $($PY --version)"
[ -n "$VIRTUAL_ENV" ] && echo "  ✓ venv: $VIRTUAL_ENV" || echo "  ⚠ Not in venv"
echo ""

#test 2: dependencies
echo -e "${YELLOW}[2/7] Dependencies${NC}"
$PY -c "import google.genai; print('  ✓ google-genai')" || exit 1
$PY -c "import pydantic; print('  ✓ pydantic')" || exit 1
$PY -c "import yaml; print('  ✓ PyYAML')" || exit 1
$PY -c "import elasticsearch; print('  ✓ elasticsearch')" || exit 1
$PY -c "import luqum; print('  ✓ luqum')" || exit 1
echo ""

#test 3: CTI loading
echo -e "${YELLOW}[3/7] CTI Loading${NC}"
$PY -c "
from detection_agent.tools.load_cti_files import load_cti_files
r = load_cti_files('cti_src')
print(f'  ✓ Loaded {r[\"files_loaded\"]} files, {len(r[\"text_content\"])} chars')
" || exit 1
echo ""

#test 4: agent imports
echo -e "${YELLOW}[4/7] Agent Imports${NC}"
$PY -c "from detection_agent.agent import run_detection_agent; print('  ✓ agent')" || exit 1
$PY -c "from detection_agent.refinement import run_with_refinement; print('  ✓ refinement')" || exit 1
$PY -c "from detection_agent.per_rule_refinement import refine_rule_with_feedback; print('  ✓ per-rule refinement')" || exit 1
$PY -c "from detection_agent.schemas.detection_rule import DetectionRuleOutput; print('  ✓ schemas')" || exit 1
echo ""

#test 5-7: script syntax
echo -e "${YELLOW}[5/7] Validation Script${NC}"
$PY -m py_compile scripts/validate_rules.py && echo "  ✓ validates.py compiles" || exit 1
echo ""

echo -e "${YELLOW}[6/7] Integration Test Script${NC}"
$PY -m py_compile scripts/integration_test_ci.py && echo "  ✓ integration_test_ci.py compiles" || exit 1
echo ""

echo -e "${YELLOW}[7/7] LLM Judge Script${NC}"
$PY -m py_compile scripts/run_llm_judge.py && echo "  ✓ run_llm_judge.py compiles" || exit 1
echo ""

echo "================================"
echo -e "${GREEN}✓ All Core Tests Passed!${NC}"
echo "================================"
echo ""
echo "Next: python run_agent.py --test-cti"
