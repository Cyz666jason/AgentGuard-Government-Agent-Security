"""生成证据优先级裁决报告，并在被取代的历史文件里写明取代关系。

历史失败文件一律保留，不删除、不改写原始测量值；只追加 ``superseded_by``
说明块，写清这份记录的测试时间、测试环境，以及现在由哪份更高优先级的证据
代表当前结论。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evidence.precedence import EvidenceResolver  # noqa: E402

REPORT = ROOT / "reports" / "evidence_precedence.json"

TRACKED_CLAIMS = (
    "opa_envoy_container_e2e",
    "toolhive_container_e2e",
    "github_public_release",
)


def annotate_superseded(resolver: EvidenceResolver, report: dict[str, Any]) -> list[str]:
    """把取代关系写回历史证据文件（只追加说明，不修改原始测量值）。"""

    annotations: dict[str, dict[str, Any]] = {}
    for claim_name, claim in report["claims"].items():
        winner = claim.get("decided_by")
        if not winner:
            continue
        for stale in claim.get("superseded_evidence", []):
            entry = annotations.setdefault(
                stale["source"],
                {
                    "note": (
                        "本文件保留为历史记录。其中的结论产生于下列测试时间与环境，"
                        "已被更高优先级的证据取代，不代表当前仓库结论。"
                    ),
                    "this_evidence_tested_at": stale["tested_at"],
                    "this_evidence_environment": stale["environment"],
                    "this_evidence_tier": stale["tier"],
                    "superseded_claims": [],
                },
            )
            entry["superseded_claims"].append(
                {
                    "claim": claim_name,
                    "recorded_verdict": stale["verdict"],
                    "current_verdict": winner["verdict"],
                    "superseded_by": winner["source"],
                    "superseding_tier": winner["tier"],
                    "superseding_tested_at": winner["tested_at"],
                    "superseding_environment": winner["environment"],
                }
            )

    written: list[str] = []
    for relative, annotation in sorted(annotations.items()):
        path = ROOT / relative
        if not path.is_file():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8-sig"))
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(payload, dict):
            continue
        annotation["superseded_claims"].sort(key=lambda item: item["claim"])
        if payload.get("superseded_by") == annotation:
            continue
        payload["superseded_by"] = annotation
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        written.append(relative)
    return written


def main() -> int:
    resolver = EvidenceResolver(ROOT)
    report = resolver.as_report(TRACKED_CLAIMS)
    annotated = annotate_superseded(resolver, report)
    report["annotated_historical_files"] = annotated
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    summary = {
        claim: {
            "verdict": value["verdict"],
            "tier": (value["decided_by"] or {}).get("tier", "no_evidence"),
            "source": (value["decided_by"] or {}).get("source", ""),
            "superseded": len(value["superseded_evidence"]),
        }
        for claim, value in report["claims"].items()
    }
    print(json.dumps({"claims": summary, "annotated": annotated}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
