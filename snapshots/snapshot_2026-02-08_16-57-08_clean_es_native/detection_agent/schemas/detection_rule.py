"""Pydantic schemas for Elasticsearch Detection Rules"""

from pydantic import BaseModel, Field, model_validator
from typing import List, Dict, Optional, Literal
from datetime import datetime


class MitreTechnique(BaseModel):
    """MITRE ATT&CK technique"""
    id: str = Field(description="Technique ID (e.g., T1490)")
    name: str = Field(description="Technique name")
    reference: str = Field(description="URL to MITRE ATT&CK page")


class MitreTactic(BaseModel):
    """MITRE ATT&CK tactic"""
    id: str = Field(description="Tactic ID (e.g., TA0040)")
    name: str = Field(description="Tactic name")
    reference: str = Field(description="URL to MITRE ATT&CK page")


class ThreatMapping(BaseModel):
    """Threat framework mapping"""
    framework: Literal["MITRE ATT&CK"] = "MITRE ATT&CK"
    tactic: MitreTactic
    technique: List[MitreTechnique]


class TestCase(BaseModel):
    """Test case for detection rule"""
    type: Literal["TP", "FN", "FP", "TN"] = Field(
        description="TP=True Positive, FN=False Negative, FP=False Positive, TN=True Negative"
    )
    description: str = Field(description="What this test case represents")
    log_entry: Dict = Field(description="ECS-formatted log entry")
    expected_match: bool = Field(description="Should this log entry match the detection rule?")
    evasion_technique: Optional[str] = Field(
        default=None,
        description="For FN: Explain the evasion technique"
    )


class DetectionRule(BaseModel):
    """Elasticsearch Detection Rule"""
    name: str = Field(description="Concise detection name (100 chars max)", max_length=100)
    description: str = Field(description="What this detects and why (2-3 sentences)")
    type: Literal["query"] = "query"
    query: str = Field(description="Lucene query string")
    language: Literal["lucene", "kuery", "eql"] = "lucene"
    index: List[str] = Field(
        default=["logs-*", "winlogbeat-*", "filebeat-*"],
        description="Elasticsearch indices to search"
    )
    filters: List[Dict] = Field(default=[], description="Additional filters")
    risk_score: int = Field(ge=0, le=100, description="Risk score 0-100")
    severity: Literal["low", "medium", "high", "critical"] = Field(
        description="Detection severity"
    )
    threat: List[ThreatMapping] = Field(description="MITRE ATT&CK mappings")
    references: List[str] = Field(description="URLs to documentation and research")
    author: List[str] = Field(default=["Detection Agent"])
    false_positives: List[str] = Field(
        description="Known false positive scenarios"
    )
    note: Optional[str] = Field(
        default=None,
        description="Triage guidance for analysts"
    )
    test_cases: List[TestCase] = Field(
        description="Test cases for validation (TP/FN/FP/TN)"
    )

    def validate_test_cases(self) -> Dict[str, str]:
        """Validate test case requirements"""
        types = [tc.type for tc in self.test_cases]
        errors = []

        if 'TP' not in types:
            errors.append("Must have at least 1 TP (True Positive) test case")
        if 'FN' not in types:
            errors.append("Must have at least 1 FN (False Negative) test case")

        if errors:
            return {"valid": False, "errors": errors}
        return {"valid": True}


class DetectionRuleOutput(BaseModel):
    """Output from detection generator agent"""
    rules: List[DetectionRule] = Field(description="Generated detection rules")
    cti_context: Dict = Field(
        description="Context from CTI source (threat actor, TTPs, environment)"
    )
    total_rules: int = Field(default=0, description="Number of rules generated")

    @model_validator(mode='after')
    def compute_total_rules(self):
        """auto-compute total_rules if not provided"""
        if not self.total_rules and self.rules:
            self.total_rules = len(self.rules)
        return self


class ValidationResult(BaseModel):
    """Result from LLM validator"""
    valid: bool
    query_syntax_score: float = Field(ge=0.0, le=1.0)
    field_mapping_score: float = Field(ge=0.0, le=1.0)
    logic_score: float = Field(ge=0.0, le=1.0)
    test_coverage_score: float = Field(ge=0.0, le=1.0)
    overall_score: float = Field(ge=0.0, le=1.0)
    issues: List[str] = Field(default=[])
    warnings: List[str] = Field(default=[])
    field_research: Optional[Dict[str, str]] = Field(
        default=None,
        description="Research results for each field"
    )
    recommendation: str


class EvaluationResult(BaseModel):
    """Result from LLM test evaluator"""
    tp_detected: int = Field(description="True positives that matched")
    tp_total: int = Field(description="Total TP test cases")
    tp_score: float = Field(description="TP score (0-40)")
    fn_documented: int = Field(description="False negatives documented")
    fn_total: int = Field(description="Total FN test cases")
    fn_score: float = Field(description="FN score (0-30)")
    fp_count: int = Field(description="False positives detected")
    fp_penalty: float = Field(description="FP penalty (-5 each)")
    tn_issues: int = Field(description="True negatives that incorrectly matched")
    tn_penalty: float = Field(description="TN penalty (-2 each)")
    quality_score: float = Field(ge=0.0, le=1.0, description="Overall quality score")
    pass_test: bool = Field(alias="pass", description="Does this pass quality threshold?")
    confidence: Literal["low", "medium", "high"]
    issues: List[str] = Field(default=[])
    strengths: List[str] = Field(default=[])
    reasoning: str = Field(description="Detailed reasoning for score")
    recommendation: str = Field(description="APPROVE/REFINE/REJECT with explanation")


class SecurityScanResult(BaseModel):
    """Result from LLM security guard"""
    risk_level: Literal["LOW", "MEDIUM", "HIGH"]
    action: Literal["ALLOW", "FLAG", "BLOCK"]
    threats_detected: List[Dict] = Field(default=[])
    analysis: str
    recommendation: str
