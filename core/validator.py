"""Result validator — re-tests findings 3x, confidence scoring."""
# For authorized security testing only.
import time
from typing import Dict, Optional
import requests
from core.utils import make_request, response_diff
from config import VALIDATION_ATTEMPTS, MIN_CONFIDENCE


class ResultValidator:
    def __init__(self, session: requests.Session):
        self.session = session
    
    def validate_finding(self, finding: Dict, test_func) -> Dict:
        """Validate a finding by re-testing it multiple times."""
        confirmations = 0
        total_attempts = VALIDATION_ATTEMPTS
        for attempt in range(total_attempts):
            try:
                confirmed = test_func(finding)
                if confirmed:
                    confirmations += 1
                time.sleep(0.3)
            except Exception:
                pass
        confidence_boost = (confirmations / total_attempts) * 30
        new_confidence = min(100, finding.get("confidence", 70) + confidence_boost)
        finding["confidence"] = int(new_confidence)
        finding["validation_attempts"] = total_attempts
        finding["validation_confirmations"] = confirmations
        return finding
    
    def calculate_confidence(
        self,
        payload_triggered: bool,
        response_different: bool,
        error_pattern_found: bool,
        content_matched: bool = False,
        timing_confirmed: bool = False,
    ) -> int:
        """Calculate confidence score based on evidence."""
        score = 0
        if payload_triggered:
            score += 40
        if response_different:
            score += 20
        if error_pattern_found:
            score += 25
        if content_matched:
            score += 10
        if timing_confirmed:
            score += 30
        return min(100, score)
    
    def is_reportable(self, confidence: int) -> bool:
        return confidence >= MIN_CONFIDENCE
