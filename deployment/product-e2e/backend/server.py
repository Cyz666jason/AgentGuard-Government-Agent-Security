import base64
import hashlib
import hmac
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


SECRET = bytes.fromhex(os.environ["AGENTGUARD_CONTAINER_TICKET_SECRET"])
if len(SECRET) < 32:
    raise RuntimeError("AGENTGUARD_CONTAINER_TICKET_SECRET must contain at least 32 bytes")
CONSUMED: set[str] = set()
CONSUMED_LOCK = threading.Lock()


def request_action_digest(method: str, path: str, body: bytes) -> str:
    canonical = json.dumps(
        {
            "method": method,
            "path": path,
            "body_sha256": hashlib.sha256(body).hexdigest(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def decode_ticket(token: str) -> dict:
    encoded, received_signature = token.split(".", 1)
    key_id, received_digest = received_signature.split(":", 1)
    if key_id != "local-v1":
        raise ValueError("unknown key version")
    expected = base64.urlsafe_b64encode(
        hmac.new(SECRET, encoded.encode("ascii"), hashlib.sha256).digest()
    ).decode("ascii").rstrip("=")
    if not hmac.compare_digest(expected, received_digest):
        raise ValueError("invalid signature")
    payload = json.loads(
        base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    )
    required = {"jti", "task_id", "action_digest", "iat", "exp"}
    if not isinstance(payload, dict) or not required.issubset(payload):
        raise ValueError("incomplete payload")
    if float(payload["exp"]) < time.time():
        raise ValueError("expired ticket")
    return payload


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length < 0 or content_length > 65536:
                raise ValueError("invalid body length")
            body = self.rfile.read(content_length)
            payload = decode_ticket(self.headers.get("X-AgentGuard-Ticket", ""))
            if payload["task_id"] != self.headers.get("X-AgentGuard-Task-ID"):
                raise ValueError("task binding mismatch")
            if payload["action_digest"] != request_action_digest(
                self.command, self.path, body
            ):
                raise ValueError("action binding mismatch")
            with CONSUMED_LOCK:
                if payload["jti"] in CONSUMED:
                    self.send_error(409, "ticket replay")
                    return
                CONSUMED.add(payload["jti"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            self.send_error(403, "invalid execution ticket")
            return
        body = b'{"status":"backend_reached_through_envoy"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
