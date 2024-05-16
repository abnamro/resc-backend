# Standard Library
from enum import Enum
from typing import TypedDict


class StatusStats(TypedDict):
    true_positive: int
    false_positive: int
    not_analyzed: int
    not_accessible: int
    clarification_required: int
    total_findings_count: int


class FindingStatus(str, Enum):
    NOT_ANALYZED = "NOT_ANALYZED"
    NOT_ACCESSIBLE = "NOT_ACCESSIBLE"
    CLARIFICATION_REQUIRED = "CLARIFICATION_REQUIRED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    TRUE_POSITIVE = "TRUE_POSITIVE"
    OUTDATED = "OUTDATED"

    @classmethod
    def init_statistics(cls) -> StatusStats:
        return {
            "true_positive": 0,
            "false_positive": 0,
            "not_analyzed": 0,
            "not_accessible": 0,
            "clarification_required": 0,
            "outdated": 0,
            "total_findings_count": 0,
        }
