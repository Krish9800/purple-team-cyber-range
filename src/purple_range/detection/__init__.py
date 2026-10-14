"""Blue Team detection verification engine and alert normalizer."""

from purple_range.detection.correlator import DetectionCorrelator
from purple_range.detection.evaluator import DetectionCoverageEvaluator
from purple_range.detection.normalizer import AlertNormalizer

__all__ = [
    "AlertNormalizer",
    "DetectionCorrelator",
    "DetectionCoverageEvaluator",
]
