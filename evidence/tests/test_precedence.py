"""证据优先级裁决测试：历史失败不得覆盖更高优先级的成功实测。"""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from evidence.precedence import (
    TIER_CI_ANCESTOR,
    TIER_CI_HEAD,
    TIER_CI_UNRELATED,
    TIER_HISTORICAL,
    TIER_LOCAL_FRESH,
    EvidenceRecord,
    EvidenceResolver,
    resolve_records,
)


def record(tier: str, verdict: bool | None, tested_at: str = "2026-01-01T00:00:00+00:00") -> EvidenceRecord:
    return EvidenceRecord(
        claim="demo_claim",
        verdict=verdict,
        tier=tier,
        source=f"reports/{tier}.json",
        tested_at=tested_at,
        environment=tier,
    )


class ResolveRecordsTests(unittest.TestCase):
    """纯裁决逻辑：不依赖文件系统或 Git。"""

    def test_ci_evidence_beats_local_historical_failure(self) -> None:
        resolved = resolve_records(
            "demo_claim",
            [
                record(TIER_HISTORICAL, False),
                record(TIER_CI_ANCESTOR, True),
            ],
        )
        self.assertTrue(resolved.verdict)
        self.assertEqual(resolved.tier, TIER_CI_ANCESTOR)

    def test_historical_failure_is_recorded_as_superseded(self) -> None:
        resolved = resolve_records(
            "demo_claim",
            [
                record(TIER_HISTORICAL, False),
                record(TIER_LOCAL_FRESH, False),
                record(TIER_CI_HEAD, True),
            ],
        )
        self.assertTrue(resolved.verdict)
        self.assertEqual(len(resolved.superseded), 2)
        self.assertEqual(
            {item.tier for item in resolved.superseded},
            {TIER_HISTORICAL, TIER_LOCAL_FRESH},
        )

    def test_fresh_local_evidence_beats_ci_from_unrelated_commit(self) -> None:
        resolved = resolve_records(
            "demo_claim",
            [
                record(TIER_CI_UNRELATED, False),
                record(TIER_LOCAL_FRESH, True),
            ],
        )
        self.assertTrue(resolved.verdict)
        self.assertEqual(resolved.tier, TIER_LOCAL_FRESH)

    def test_same_tier_prefers_later_test_time(self) -> None:
        resolved = resolve_records(
            "demo_claim",
            [
                record(TIER_LOCAL_FRESH, False, "2026-01-01T00:00:00+00:00"),
                record(TIER_LOCAL_FRESH, True, "2026-06-01T00:00:00+00:00"),
            ],
        )
        self.assertTrue(resolved.verdict)

    def test_agreeing_lower_tier_is_not_marked_superseded(self) -> None:
        resolved = resolve_records(
            "demo_claim",
            [record(TIER_HISTORICAL, True), record(TIER_CI_HEAD, True)],
        )
        self.assertEqual(resolved.superseded, ())

    def test_unmeasured_records_do_not_decide(self) -> None:
        resolved = resolve_records(
            "demo_claim",
            [record(TIER_CI_HEAD, None), record(TIER_HISTORICAL, False)],
        )
        self.assertFalse(resolved.verdict)
        self.assertEqual(resolved.tier, TIER_HISTORICAL)

    def test_no_evidence_yields_none_not_false(self) -> None:
        resolved = resolve_records("demo_claim", [])
        self.assertIsNone(resolved.verdict)
        self.assertEqual(resolved.tier, "no_evidence")


class ResolverIntegrationTests(unittest.TestCase):
    """在临时 Git 仓库里验证提交关系判定与端到端裁决。"""

    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.root = Path(self._temp.name)
        self.reports = self.root / "reports"
        self.reports.mkdir()
        self._git("init", "--initial-branch=main")
        self._git("config", "user.email", "test@example.invalid")
        self._git("config", "user.name", "AgentGuard Test")
        (self.root / "seed.txt").write_text("seed", encoding="utf-8")
        self._git("add", "seed.txt")
        self._git("commit", "-m", "seed")
        self.first_commit = self._git("rev-parse", "HEAD")
        (self.root / "seed.txt").write_text("second", encoding="utf-8")
        self._git("add", "seed.txt")
        self._git("commit", "-m", "second")
        self.head_commit = self._git("rev-parse", "HEAD")

    def tearDown(self) -> None:
        self._temp.cleanup()

    def _git(self, *args: str) -> str:
        # 固定 UTF-8：中文 Windows 的 GBK 默认编码无法解码 git 的本地化输出。
        completed = subprocess.run(
            ["git", *args],
            cwd=self.root,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        )
        return (completed.stdout or "").strip()

    def _write(self, name: str, payload: dict) -> None:
        path = self.reports / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(payload, ensure_ascii=False), encoding="utf-8"
        )

    def _write_ci(self, commit: str, passed: bool = True) -> None:
        self._write(
            "e2e/network/github_actions_container_product_e2e.json",
            {
                "commit": commit,
                "runner": "ubuntu-latest",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "passed": 10 if passed else 3,
                "total": 10,
                "opa_envoy_container_e2e": passed,
                "toolhive_container_e2e": passed,
                "workflow_url": "https://example.invalid/run/1",
            },
        )

    def _write_local_failure(self, generated_at: datetime) -> None:
        self._write(
            "e2e/network/container_product_e2e_attempt.json",
            {
                "run_id": "local-1",
                "generated_at": generated_at.isoformat(),
                "runtime": "docker",
                "status": "failed",
                "opa_envoy_container_e2e": False,
                "toolhive_container_e2e": False,
                "failure": {"message": "Envoy did not become reachable"},
            },
        )

    def test_no_docker_history_does_not_override_linux_runner_success(self) -> None:
        self._write_ci(self.first_commit, passed=True)
        self._write_local_failure(datetime.now(timezone.utc) - timedelta(days=30))
        self._write(
            "preflight/toolhive_environment_check.json",
            {
                "tested_at": "2026-08-07T08:43:13+08:00",
                "container_e2e_tested": False,
                "reason": "no container runtime",
            },
        )
        resolver = EvidenceResolver(self.root)
        envoy = resolver.resolve("opa_envoy_container_e2e")
        toolhive = resolver.resolve("toolhive_container_e2e")
        self.assertTrue(envoy.verdict)
        self.assertTrue(toolhive.verdict)
        self.assertEqual(envoy.tier, TIER_CI_ANCESTOR)
        self.assertTrue(envoy.superseded)

    def test_head_commit_evidence_ranks_above_ancestor(self) -> None:
        self._write_ci(self.head_commit, passed=True)
        resolver = EvidenceResolver(self.root)
        self.assertEqual(
            resolver.resolve("opa_envoy_container_e2e").tier, TIER_CI_HEAD
        )

    def test_unknown_commit_is_treated_as_unrelated(self) -> None:
        self._write_ci("0" * 40, passed=True)
        resolver = EvidenceResolver(self.root)
        self.assertEqual(
            resolver.resolve("opa_envoy_container_e2e").tier, TIER_CI_UNRELATED
        )

    def test_fresh_local_failure_overrides_unrelated_ci_success(self) -> None:
        self._write_ci("0" * 40, passed=True)
        self._write_local_failure(datetime.now(timezone.utc))
        resolver = EvidenceResolver(self.root)
        envoy = resolver.resolve("opa_envoy_container_e2e")
        self.assertFalse(envoy.verdict)
        self.assertEqual(envoy.tier, TIER_LOCAL_FRESH)

    def test_ci_failure_at_head_is_not_masked_by_stale_local_success(self) -> None:
        """CI 在当前提交失败时，不允许被更旧的本机成功记录掩盖。"""

        self._write_ci(self.head_commit, passed=False)
        self._write(
            "e2e/network/container_product_e2e_attempt.json",
            {
                "run_id": "local-1",
                "generated_at": (
                    datetime.now(timezone.utc) - timedelta(days=30)
                ).isoformat(),
                "runtime": "docker",
                "status": "passed",
                "opa_envoy_container_e2e": True,
                "toolhive_container_e2e": True,
            },
        )
        resolver = EvidenceResolver(self.root)
        self.assertFalse(resolver.resolve("opa_envoy_container_e2e").verdict)

    def test_publication_evidence_requires_public_visibility(self) -> None:
        self._write(
            "status/github_publication.json",
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "published": True,
                "visibility": "private",
                "remote_url": "https://example.invalid/repo.git",
                "probe_method": "gh_repo_view",
            },
        )
        resolver = EvidenceResolver(self.root)
        self.assertFalse(resolver.resolve("github_public_release").verdict)

    def test_public_visibility_resolves_to_published(self) -> None:
        self._write(
            "status/github_publication.json",
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "published": True,
                "visibility": "public",
                "remote_url": "https://example.invalid/repo.git",
                "probe_method": "anonymous_git_ls_remote",
            },
        )
        resolver = EvidenceResolver(self.root)
        self.assertTrue(resolver.resolve("github_public_release").verdict)

    def test_missing_reports_yield_no_evidence(self) -> None:
        resolver = EvidenceResolver(self.root)
        self.assertIsNone(resolver.resolve("opa_envoy_container_e2e").verdict)

    def test_report_records_precedence_rule_and_head(self) -> None:
        self._write_ci(self.first_commit, passed=True)
        resolver = EvidenceResolver(self.root)
        report = resolver.as_report(["opa_envoy_container_e2e"])
        self.assertEqual(report["head_commit"], self.head_commit)
        self.assertIn("claims", report)
        self.assertIn("opa_envoy_container_e2e", report["claims"])
        ranks = [entry["rank"] for entry in report["precedence_order"]]
        self.assertEqual(ranks, sorted(ranks, reverse=True))


if __name__ == "__main__":
    unittest.main()
