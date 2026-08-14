"""Loopback-only, allowlisted cache for Alpine packages used by the QEMU lab."""

from __future__ import annotations

import argparse
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
CACHE_ROOT = ROOT / "third_party" / "cache" / "alpine"
UPSTREAM = "https://mirrors.cloud.tencent.com"
ALLOWED_PREFIX = PurePosixPath("/alpine/v3.24")
locks: dict[Path, threading.Lock] = {}
locks_guard = threading.Lock()


def lock_for(path: Path) -> threading.Lock:
    with locks_guard:
        return locks.setdefault(path, threading.Lock())


def resolve_request(raw_path: str) -> tuple[Path, str]:
    path = PurePosixPath(unquote(urlsplit(raw_path).path))
    if ".." in path.parts or not path.is_relative_to(ALLOWED_PREFIX):
        raise ValueError("path outside allowlisted Alpine v3.24 repository")
    if len(path.parts) < 6 or path.parts[3] not in {"main", "community"}:
        raise ValueError("only Alpine main/community repositories are allowed")
    relative = Path(*path.parts[1:])
    target = (CACHE_ROOT / relative).resolve()
    if CACHE_ROOT.resolve() not in target.parents:
        raise ValueError("resolved cache path escaped cache root")
    return target, UPSTREAM + path.as_posix()


def ensure_cached(target: Path, upstream: str) -> None:
    if target.exists() and target.stat().st_size > 0:
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_suffix(target.suffix + ".part")
    with lock_for(target):
        if target.exists() and target.stat().st_size > 0:
            return
        completed = subprocess.run(
            [
                "curl.exe",
                "-fL",
                "-C",
                "-",
                "--retry",
                "20",
                "--retry-all-errors",
                "--retry-delay",
                "1",
                upstream,
                "-o",
                str(partial),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=1800,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr[-2000:])
        os.replace(partial, target)


class Handler(BaseHTTPRequestHandler):
    server_version = "AgentGuardAlpineCache/1.0"

    def do_HEAD(self) -> None:
        self._serve(send_body=False)

    def do_GET(self) -> None:
        self._serve(send_body=True)

    def _serve(self, *, send_body: bool) -> None:
        try:
            target, upstream = resolve_request(self.path)
            ensure_cached(target, upstream)
            size = target.stat().st_size
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(size))
            self.end_headers()
            if send_body:
                with target.open("rb") as source:
                    while chunk := source.read(1024 * 1024):
                        self.wfile.write(chunk)
        except ValueError as exc:
            self.send_error(403, str(exc))
        except Exception as exc:
            self.send_error(502, f"upstream cache failure: {type(exc).__name__}")

    def log_message(self, format: str, *args) -> None:
        print(f"{self.client_address[0]} {format % args}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18090)
    args = parser.parse_args()
    CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Alpine cache listening on {args.host}:{args.port}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
