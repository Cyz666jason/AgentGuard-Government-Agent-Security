"""按明确优先级解析互相冲突的测试证据。

项目在不同环境下产生过互相矛盾的记录：本机 Windows 没有容器运行时，因此
``reports/e2e/network/container_product_e2e_attempt.json`` 与
``reports/preflight/toolhive_environment_check.json`` 记录的是失败或"未运行"；而
``reports/e2e/network/github_actions_container_product_e2e.json`` 记录的是 GitHub Linux
Runner 上 10/10 通过的实测。

这里不手工写死结论，而是实现一条可复用的优先级规则：

1. 与当前提交历史匹配的 CI 实测证据；
2. 当前机器产生的新鲜实测证据；
3. 与当前提交无关的 CI 证据；
4. 历史环境检查与历史失败记录。

历史失败记录被保留，但只作为背景，并在解析结果里标明被哪份新证据取代。
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPORTS = PROJECT_ROOT / "reports"

TIER_CI_HEAD = "ci_evidence_head_commit"
TIER_CI_ANCESTOR = "ci_evidence_ancestor_commit"
TIER_LOCAL_FRESH = "local_fresh_evidence"
TIER_CI_UNRELATED = "ci_evidence_unrelated_commit"
TIER_HISTORICAL = "historical_environment_check"

TIER_RANK: dict[str, int] = {
    TIER_CI_HEAD: 50,
    TIER_CI_ANCESTOR: 40,
    TIER_LOCAL_FRESH: 30,
    TIER_CI_UNRELATED: 20,
    TIER_HISTORICAL: 10,
}

DEFAULT_FRESH_HOURS = 24.0


@dataclass(frozen=True)
class EvidenceRecord:
    """一条具体证据：某个断言在某个环境、某个时间点的实测结论。"""

    claim: str
    verdict: bool | None
    tier: str
    source: str
    tested_at: str
    environment: str
    detail: str = ""
    commit: str = ""

    @property
    def rank(self) -> int:
        return TIER_RANK.get(self.tier, 0)

    def as_dict(self) -> dict[str, Any]:
        return {
            "claim": self.claim,
            "verdict": self.verdict,
            "tier": self.tier,
            "tier_rank": self.rank,
            "source": self.source,
            "tested_at": self.tested_at,
            "environment": self.environment,
            "commit": self.commit,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class ResolvedClaim:
    """某个断言的最终结论，以及被它取代的历史记录。"""

    claim: str
    winning: EvidenceRecord | None
    superseded: tuple[EvidenceRecord, ...] = field(default_factory=tuple)

    @property
    def verdict(self) -> bool | None:
        return None if self.winning is None else self.winning.verdict

    @property
    def tier(self) -> str:
        return "no_evidence" if self.winning is None else self.winning.tier

    @property
    def source(self) -> str:
        return "" if self.winning is None else self.winning.source

    def as_dict(self) -> dict[str, Any]:
        return {
            "claim": self.claim,
            "verdict": self.verdict,
            "decided_by": None if self.winning is None else self.winning.as_dict(),
            "superseded_evidence": [item.as_dict() for item in self.superseded],
        }


def resolve_records(claim: str, records: Iterable[EvidenceRecord]) -> ResolvedClaim:
    """纯函数版裁决：同一断言的多条证据里，层级最高者代表当前结论。

    同层级时以记录的测试时间更晚者为准。verdict 为 ``None``（未测量）的记录
    不参与裁决。结论不同的低层级记录进入 ``superseded``，供报告标注取代关系。
    """

    candidates = [item for item in records if item.verdict is not None]
    if not candidates:
        return ResolvedClaim(claim=claim, winning=None, superseded=())
    ordered = sorted(
        candidates,
        key=lambda item: (item.rank, item.tested_at),
        reverse=True,
    )
    winner = ordered[0]
    superseded = tuple(item for item in ordered[1:] if item.verdict != winner.verdict)
    return ResolvedClaim(claim=claim, winning=winner, superseded=superseded)


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, OSError):
        return None
    return payload if isinstance(payload, dict) else None


def _relative(path: Path) -> str:
    try:
        return path.relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _git(root: Path, *args: str) -> tuple[int, str]:
    """调用 git 并显式按 UTF-8 解码。

    中文 Windows 的默认 ``locale`` 编码是 GBK，git 的本地化输出会让
    ``text=True`` 在解码线程里抛 ``UnicodeDecodeError`` 并把 stdout 变成
    ``None``；因此这里固定 UTF-8 并容错替换。
    """

    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=root,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except (OSError, ValueError):
        return 127, ""
    return completed.returncode, (completed.stdout or "").strip()


class EvidenceResolver:
    """从 ``reports/`` 目录收集证据并按优先级给出唯一结论。"""

    def __init__(
        self,
        root: Path | str = PROJECT_ROOT,
        fresh_hours: float = DEFAULT_FRESH_HOURS,
        now: datetime | None = None,
    ) -> None:
        self.root = Path(root).resolve()
        self.reports = self.root / "reports"
        self.fresh_hours = fresh_hours
        self.now = now or datetime.now(timezone.utc)
        self._head = self._resolve_head()
        self._records: dict[str, list[EvidenceRecord]] = {}
        self._collect()

    # ---------------------------------------------------------------- git

    @property
    def head_commit(self) -> str:
        """裁决基准提交；不在 Git 工作区时为空字符串。"""

        return self._head

    def _resolve_head(self) -> str:
        code, out = _git(self.root, "rev-parse", "HEAD")
        return out if code == 0 else ""

    def commit_relation(self, commit: str) -> str:
        """返回 CI 证据提交与当前 HEAD 的关系对应的优先级层级。"""

        commit = (commit or "").strip()
        if not commit or not self._head:
            return TIER_CI_UNRELATED
        if commit == self._head:
            return TIER_CI_HEAD
        code, _ = _git(self.root, "merge-base", "--is-ancestor", commit, "HEAD")
        return TIER_CI_ANCESTOR if code == 0 else TIER_CI_UNRELATED

    def commits_since(self, commit: str) -> int | None:
        commit = (commit or "").strip()
        if not commit or not self._head:
            return None
        code, out = _git(self.root, "rev-list", "--count", f"{commit}..HEAD")
        if code != 0 or not out.isdigit():
            return None
        return int(out)

    # --------------------------------------------------------- freshness

    def _is_fresh(self, path: Path, payload: Mapping[str, Any] | None = None) -> bool:
        stamp = None
        if payload is not None:
            stamp = self._parse_time(str(payload.get("generated_at", "")))
        if stamp is None and path.is_file():
            stamp = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        if stamp is None:
            return False
        age_hours = (self.now - stamp).total_seconds() / 3600.0
        return -1.0 <= age_hours <= self.fresh_hours

    @staticmethod
    def _parse_time(raw: str) -> datetime | None:
        raw = raw.strip()
        if not raw:
            return None
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)

    # --------------------------------------------------------- collection

    def _add(self, record: EvidenceRecord) -> None:
        self._records.setdefault(record.claim, []).append(record)

    def _collect(self) -> None:
        self._collect_ci_container_evidence()
        self._collect_local_container_evidence()
        self._collect_historical_environment_evidence()
        self._collect_publication_evidence()

    def _collect_ci_container_evidence(self) -> None:
        path = self.reports / "e2e" / "network" / "github_actions_container_product_e2e.json"
        payload = _load_json(path)
        if payload is None:
            return
        commit = str(payload.get("commit", ""))
        tier = self.commit_relation(commit)
        since = self.commits_since(commit)
        runner = str(payload.get("runner", "unknown-runner"))
        url = str(payload.get("workflow_url", ""))
        passed = payload.get("passed")
        total = payload.get("total")
        detail = f"GitHub Actions {runner} {passed}/{total}；{url}"
        if since:
            detail += f"；该提交之后本地又有 {since} 个提交，未被这次 CI 覆盖"
        for claim, key in (
            ("opa_envoy_container_e2e", "opa_envoy_container_e2e"),
            ("toolhive_container_e2e", "toolhive_container_e2e"),
        ):
            value = payload.get(key)
            self._add(
                EvidenceRecord(
                    claim=claim,
                    verdict=bool(value) if value is not None else None,
                    tier=tier,
                    source=_relative(path),
                    tested_at=str(payload.get("generated_at", "")),
                    environment=f"github_actions/{runner}",
                    detail=detail,
                    commit=commit,
                )
            )

    def _collect_local_container_evidence(self) -> None:
        path = self.reports / "e2e" / "network" / "container_product_e2e_attempt.json"
        payload = _load_json(path)
        if payload is None:
            return
        fresh = self._is_fresh(path, payload)
        tier = TIER_LOCAL_FRESH if fresh else TIER_HISTORICAL
        failure = payload.get("failure") or {}
        detail = (
            f"本机 runtime={payload.get('runtime', 'unknown')}；"
            f"status={payload.get('status', 'unknown')}"
        )
        if isinstance(failure, Mapping) and failure.get("message"):
            detail += f"；failure={failure.get('message')}"
        for claim, key in (
            ("opa_envoy_container_e2e", "opa_envoy_container_e2e"),
            ("toolhive_container_e2e", "toolhive_container_e2e"),
        ):
            self._add(
                EvidenceRecord(
                    claim=claim,
                    verdict=bool(payload.get(key, False)),
                    tier=tier,
                    source=_relative(path),
                    tested_at=str(payload.get("generated_at", "")),
                    environment="local_windows_test_machine",
                    detail=detail,
                )
            )

    def _collect_historical_environment_evidence(self) -> None:
        toolhive_path = self.reports / "preflight" / "toolhive_environment_check.json"
        toolhive = _load_json(toolhive_path)
        if toolhive is not None:
            self._add(
                EvidenceRecord(
                    claim="toolhive_container_e2e",
                    verdict=bool(toolhive.get("container_e2e_tested", False)),
                    tier=TIER_HISTORICAL,
                    source=_relative(toolhive_path),
                    tested_at=str(toolhive.get("tested_at", "")),
                    environment="local_windows_test_machine",
                    detail=str(toolhive.get("reason", "")),
                )
            )

        machine_path = self.reports / "preflight" / "test_machine_environment.json"
        machine = _load_json(machine_path)
        containers = (machine or {}).get("container_environment")
        if isinstance(containers, Mapping):
            reason = str(containers.get("reason", ""))
            tested_at = str((machine or {}).get("tested_at", ""))
            for claim, key in (
                ("opa_envoy_container_e2e", "opa_envoy_end_to_end_tested"),
                ("toolhive_container_e2e", "toolhive_container_tested"),
            ):
                self._add(
                    EvidenceRecord(
                        claim=claim,
                        verdict=bool(containers.get(key, False)),
                        tier=TIER_HISTORICAL,
                        source=_relative(machine_path),
                        tested_at=tested_at,
                        environment="local_windows_test_machine",
                        detail=reason,
                    )
                )

    def _collect_publication_evidence(self) -> None:
        path = self.reports / "status" / "github_publication.json"
        payload = _load_json(path)
        if payload is not None:
            visibility = str(payload.get("visibility", "unknown"))
            self._add(
                EvidenceRecord(
                    claim="github_public_release",
                    verdict=bool(payload.get("published", False))
                    and visibility == "public",
                    tier=(
                        TIER_LOCAL_FRESH
                        if self._is_fresh(path, payload)
                        else TIER_HISTORICAL
                    ),
                    source=_relative(path),
                    tested_at=str(payload.get("generated_at", "")),
                    environment="git_remote_probe",
                    detail=(
                        f"remote={payload.get('remote_url', '')}；"
                        f"visibility={visibility}；"
                        f"probe={payload.get('probe_method', 'unknown')}"
                    ),
                )
            )

        # 仅采集原始探测记录。``productionization_status.json`` 与
        # ``open_source_route_progress.json`` 是本模块的下游产物，不能再作为
        # 输入证据，否则会形成自证循环。

    # --------------------------------------------------------- resolution

    def records(self, claim: str) -> list[EvidenceRecord]:
        return list(self._records.get(claim, []))

    def claims(self) -> list[str]:
        return sorted(self._records)

    def resolve(self, claim: str) -> ResolvedClaim:
        return resolve_records(claim, self.records(claim))

    def resolve_all(self, claims: Iterable[str] | None = None) -> dict[str, ResolvedClaim]:
        names = list(claims) if claims is not None else self.claims()
        return {name: self.resolve(name) for name in names}

    def as_report(self, claims: Iterable[str] | None = None) -> dict[str, Any]:
        resolved = self.resolve_all(claims)
        return {
            "schema_version": "1.0.0",
            "generated_at": self.now.astimezone().isoformat(timespec="seconds"),
            "head_commit": self._head,
            "precedence_order": [
                {"tier": tier, "rank": rank}
                for tier, rank in sorted(
                    TIER_RANK.items(), key=lambda pair: pair[1], reverse=True
                )
            ],
            "fresh_window_hours": self.fresh_hours,
            "rule": (
                "与当前提交历史匹配的 CI 实测证据优先于本机新鲜证据，"
                "本机新鲜证据优先于历史环境检查与历史失败记录；"
                "本机缺少容器运行时的历史失败不得覆盖 Linux Runner 的成功结果。"
            ),
            "claims": {name: item.as_dict() for name, item in resolved.items()},
        }
