"""证据优先级解析：决定哪一份实测记录代表当前结论。"""

from .precedence import (
    EvidenceRecord,
    EvidenceResolver,
    ResolvedClaim,
    TIER_RANK,
    resolve_records,
)

__all__ = [
    "EvidenceRecord",
    "EvidenceResolver",
    "ResolvedClaim",
    "TIER_RANK",
    "resolve_records",
]
