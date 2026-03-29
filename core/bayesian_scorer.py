"""Bayesian Confidence Scorer — probabilistic evidence fusion.

Hydra Edition (v8.0) introduces Bayesian confidence scoring that replaces
simple additive scoring with principled probabilistic inference.  Each
piece of evidence updates a prior probability via Bayes' theorem,
producing a posterior confidence that naturally accounts for the
reliability and independence of evidence signals.

This dramatically reduces false positives because weak evidence doesn't
stack linearly — it must overcome the prior skepticism.

For authorized security testing only.
"""
import logging
import math
from typing import Dict, List, Optional

from config import BAYESIAN_PRIOR_CONFIDENCE

logger = logging.getLogger("venomstrike.bayesian_scorer")


class BayesianConfidenceScorer:
    """Score vulnerability confidence using Bayesian inference.

    Each evidence signal has a **likelihood ratio**: how much more likely
    the evidence is to appear when the vulnerability IS real vs. when it
    is NOT.  The scorer updates the prior probability with each signal
    using Bayes' theorem.

    Evidence signals and their likelihood ratios:

    +-----------------------+----------+------+----------------------------+
    | Signal                | P(E|H)   | P(E|~H) | LR (likelihood ratio)  |
    +-----------------------+----------+------+----------------------------+
    | error_pattern         | 0.85     | 0.05 | 17.0                       |
    | payload_reflected     | 0.80     | 0.10 | 8.0                        |
    | timing_confirmed      | 0.75     | 0.08 | 9.375                      |
    | response_diff         | 0.70     | 0.20 | 3.5                        |
    | baseline_clean        | 0.90     | 0.40 | 2.25                       |
    | retest_confirmed      | 0.95     | 0.05 | 19.0                       |
    | content_match         | 0.70     | 0.15 | 4.67                       |
    | entropy_anomaly       | 0.65     | 0.20 | 3.25                       |
    | cross_correlated      | 0.80     | 0.10 | 8.0                        |
    | oob_verified          | 0.99     | 0.01 | 99.0                       |
    | triple_confirmed      | 0.98     | 0.02 | 49.0                       |
    | waf_bypass_success    | 0.60     | 0.15 | 4.0                        |
    | chain_correlated      | 0.70     | 0.15 | 4.67                       |
    +-----------------------+----------+------+----------------------------+

    Usage::

        scorer = BayesianConfidenceScorer()
        result = scorer.score(evidence_signals={
            "error_pattern": True,
            "baseline_clean": True,
            "retest_confirmed": True,
        })
        confidence = result["confidence"]  # 0-100
    """

    # Likelihood ratios: P(evidence | vuln is real) / P(evidence | vuln is NOT real)
    EVIDENCE_LIKELIHOOD_RATIOS: Dict[str, float] = {
        "error_pattern": 17.0,
        "payload_reflected": 8.0,
        "timing_confirmed": 9.375,
        "response_diff": 3.5,
        "baseline_clean": 2.25,
        "retest_confirmed": 19.0,
        "content_match": 4.67,
        "entropy_anomaly": 3.25,
        "cross_correlated": 8.0,
        "oob_verified": 99.0,
        "triple_confirmed": 49.0,
        "waf_bypass_success": 4.0,
        "chain_correlated": 4.67,
    }

    # Inverse likelihood ratios: P(~evidence | vuln is real) / P(~evidence | vuln is NOT real)
    # When evidence is ABSENT, it mildly reduces confidence
    ABSENT_EVIDENCE_RATIOS: Dict[str, float] = {
        "error_pattern": 0.16,  # 0.15 / 0.95
        "payload_reflected": 0.22,  # 0.20 / 0.90
        "timing_confirmed": 0.27,  # 0.25 / 0.92
        "response_diff": 0.375,  # 0.30 / 0.80
        "baseline_clean": 0.167,  # 0.10 / 0.60
        "retest_confirmed": 0.053,  # 0.05 / 0.95
    }

    def __init__(self, prior: float = None):
        """Initialize with a prior probability.

        Args:
            prior: Prior probability of a vulnerability being real (0-1).
                Defaults to BAYESIAN_PRIOR_CONFIDENCE from config.
        """
        self._prior = prior if prior is not None else BAYESIAN_PRIOR_CONFIDENCE
        if not 0 < self._prior < 1:
            self._prior = 0.3

    def score(
        self,
        evidence_signals: Dict[str, bool],
        prior_override: float = None,
    ) -> Dict:
        """Calculate Bayesian confidence from evidence signals.

        Args:
            evidence_signals: Dict mapping signal names to True/False.
                True means the signal was observed; False means it was
                checked but not found.  Signals not in the dict are
                treated as "not checked" (ignored).
            prior_override: Optional override for the prior probability.

        Returns:
            Dict with ``confidence`` (0-100), ``posterior`` (0.0-1.0),
            ``prior``, ``log_odds_shift``, ``evidence_contributions``,
            ``signals_used``.
        """
        prior = prior_override if prior_override is not None else self._prior
        prior = max(0.001, min(0.999, prior))  # Clamp to avoid log(0)

        # Convert prior to log-odds
        log_odds = math.log(prior / (1 - prior))
        contributions: Dict[str, float] = {}

        for signal, observed in evidence_signals.items():
            if observed and signal in self.EVIDENCE_LIKELIHOOD_RATIOS:
                lr = self.EVIDENCE_LIKELIHOOD_RATIOS[signal]
                shift = math.log(lr)
                log_odds += shift
                contributions[signal] = round(shift, 4)
            elif not observed and signal in self.ABSENT_EVIDENCE_RATIOS:
                lr = self.ABSENT_EVIDENCE_RATIOS[signal]
                shift = math.log(lr)
                log_odds += shift
                contributions[signal] = round(shift, 4)

        # Convert back from log-odds to probability
        posterior = 1.0 / (1.0 + math.exp(-log_odds))
        confidence = int(round(posterior * 100))
        confidence = max(0, min(100, confidence))

        return {
            "confidence": confidence,
            "posterior": round(posterior, 4),
            "prior": round(prior, 4),
            "log_odds_shift": round(log_odds - math.log(prior / (1 - prior)), 4),
            "evidence_contributions": contributions,
            "signals_used": len(contributions),
        }

    def combine_with_existing(
        self,
        existing_confidence: int,
        evidence_signals: Dict[str, bool],
    ) -> Dict:
        """Combine Bayesian scoring with an existing confidence score.

        Uses the existing confidence as the prior, then applies Bayesian
        updates.  This allows the Bayesian scorer to refine confidence
        from the traditional additive scoring.

        Args:
            existing_confidence: Current confidence (0-100).
            evidence_signals: Evidence signals to apply.

        Returns:
            Same format as ``score()``.
        """
        # Use existing confidence as prior (scaled to 0-1)
        prior = max(0.01, min(0.99, existing_confidence / 100.0))
        return self.score(evidence_signals, prior_override=prior)

    @staticmethod
    def classify_confidence(confidence: int) -> str:
        """Classify a confidence value into a human-readable category.

        Returns:
            One of: "very_high", "high", "medium", "low", "very_low".
        """
        if confidence >= 90:
            return "very_high"
        elif confidence >= 70:
            return "high"
        elif confidence >= 50:
            return "medium"
        elif confidence >= 30:
            return "low"
        else:
            return "very_low"
