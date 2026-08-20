"""实测远程仓库是否已经发布以及可见性，不记录任何令牌。

优先使用已登录的 GitHub CLI 读取仓库元数据；没有 CLI 时退化为"禁用凭据助手的
匿名 ``git ls-remote``"——匿名可读即证明仓库是公开的。任何一种探测都不会把
令牌、密码或 Authorization 头写入报告。
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "reports" / "github_publication.json"
SLUG_PATTERN = re.compile(
    r"github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/?$", re.IGNORECASE
)


def run(command: list[str], timeout: float = 30.0, env: dict[str, str] | None = None) -> tuple[int, str, str]:
    # 固定 UTF-8 解码：中文 Windows 的 GBK 默认编码会让 git/gh 的本地化输出
    # 在 subprocess 解码线程里抛 UnicodeDecodeError，并把 stdout 变成 None。
    merged = {**os.environ, **(env or {})}
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            env=merged,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, "", f"{type(exc).__name__}: {exc}"
    return (
        completed.returncode,
        (completed.stdout or "").strip(),
        (completed.stderr or "").strip(),
    )


def sanitize(text: str) -> str:
    """删除可能出现在 git/gh 错误输出里的凭据片段。"""

    text = re.sub(r"://[^@\s/]+@", "://***@", text)
    text = re.sub(r"gh[pousr]_[A-Za-z0-9]{10,}", "***", text)
    text = re.sub(r"github_pat_[A-Za-z0-9_]{10,}", "***", text)
    return text[:400]


def remote_url() -> str:
    code, out, _ = run(["git", "remote", "get-url", "origin"])
    if code != 0:
        return ""
    return re.sub(r"://[^@\s/]+@", "://", out.splitlines()[0].strip())


def repository_slug(url: str) -> str:
    match = SLUG_PATTERN.search(url)
    if not match:
        return ""
    return f"{match.group('owner')}/{match.group('repo')}"


def probe_with_gh(slug: str) -> dict[str, Any] | None:
    if not slug or shutil.which("gh") is None:
        return None
    code, out, err = run(
        [
            "gh",
            "repo",
            "view",
            slug,
            "--json",
            "name,owner,visibility,isPrivate,url,defaultBranchRef,pushedAt",
        ],
        timeout=45.0,
    )
    if code != 0:
        return {"probe_method": "gh_repo_view", "error": sanitize(err or out)}
    try:
        payload = json.loads(out)
    except json.JSONDecodeError:
        return {"probe_method": "gh_repo_view", "error": "gh 输出不是合法 JSON"}
    return {
        "probe_method": "gh_repo_view",
        "visibility": str(payload.get("visibility", "")).lower() or "unknown",
        "is_private": bool(payload.get("isPrivate", True)),
        "url": str(payload.get("url", "")),
        "default_branch": str((payload.get("defaultBranchRef") or {}).get("name", "")),
        "pushed_at": str(payload.get("pushedAt", "")),
    }


def probe_anonymously(url: str) -> dict[str, Any] | None:
    """禁用凭据助手后仍能读取远端 = 仓库对匿名用户公开。"""

    if not url:
        return None
    code, out, err = run(
        [
            "git",
            "-c",
            "credential.helper=",
            "-c",
            "credential.interactive=never",
            "ls-remote",
            "--heads",
            url,
        ],
        timeout=60.0,
        env={"GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never"},
    )
    if code != 0:
        return {
            "probe_method": "anonymous_git_ls_remote",
            "anonymous_readable": False,
            "error": sanitize(err or out),
        }
    branches = [line.split("\t")[-1] for line in out.splitlines() if "\t" in line]
    return {
        "probe_method": "anonymous_git_ls_remote",
        "anonymous_readable": True,
        "remote_branches": sorted(branches),
    }


def main() -> int:
    url = remote_url()
    slug = repository_slug(url)
    gh_result = probe_with_gh(slug)
    anonymous = probe_anonymously(url)

    visibility = "unknown"
    published = False
    if gh_result and gh_result.get("visibility") in {"public", "private", "internal"}:
        visibility = str(gh_result["visibility"])
        published = True
    if anonymous and anonymous.get("anonymous_readable"):
        published = True
        if visibility == "unknown":
            visibility = "public"

    if published and visibility == "public":
        status = "published_public"
    elif published and visibility in {"private", "internal"}:
        status = f"published_{visibility}"
    elif url:
        status = "remote_configured_not_verified"
    else:
        status = "no_remote_configured"

    report: dict[str, Any] = {
        "run_id": os.environ.get("AGENTGUARD_RUN_ID", "standalone"),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "remote_url": url,
        "repository": slug,
        "published": published,
        "visibility": visibility,
        "status": status,
        "probe_method": (anonymous or gh_result or {}).get("probe_method", "none"),
        "gh_probe": gh_result,
        "anonymous_probe": anonymous,
        "secret_values_recorded": False,
        "boundary": (
            "该报告只证明远程仓库存在且可读，不证明仓库内容已经通过生产验收。"
        ),
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"status": status, "visibility": visibility, "repository": slug}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
