"""只在本次运行器的 Tailscale 地址上接收会话心跳和停止请求。"""

import datetime
import hmac
import ipaddress
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

CONTROL_PORT = 43127
MAX_JOB_SECONDS = 6 * 60 * 60
CLEANUP_SECONDS = 60
STARTUP_SECONDS = 120
HEARTBEAT_TIMEOUT = 90
REQUEST_TIMEOUT = 5
TAILNET_IPV4 = ipaddress.ip_network("100.64.0.0/10")


def session_id():
    value = os.environ.get("MNSJ_SESSION_ID", "")
    if re.fullmatch(r"[0-9a-f]{32}", value) is None:
        raise ValueError("invalid session ID")
    return value


def job_deadline():
    repository = os.environ["GITHUB_REPOSITORY"]
    run_id = int(os.environ["GITHUB_RUN_ID"])
    attempt = int(os.environ["GITHUB_RUN_ATTEMPT"])
    url = f"https://api.github.com/repos/{repository}/actions/runs/{run_id}/attempts/{attempt}/jobs"
    request = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {os.environ['GH_TOKEN']}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
        "User-Agent": "mnsj-tunnel-runner",
    })
    with urllib.request.urlopen(request, timeout=10) as response:
        jobs = json.load(response)["jobs"]
    starts = [job["started_at"] for job in jobs if job.get("started_at")]
    if not starts:
        raise ValueError("job start time unavailable")
    started = datetime.datetime.fromisoformat(min(starts).replace("Z", "+00:00"))
    return int(started.timestamp()) + MAX_JOB_SECONDS - CLEANUP_SECONDS


class Session:
    def __init__(self):
        self.id = session_id()
        self.token = os.environ["MNSJ_CONTROL_TOKEN"]
        if len(self.token) < 32:
            raise ValueError("invalid control token")
        self.deadline = job_deadline()
        self.started = time.monotonic()
        self.last_heartbeat = None
        self.stopped = threading.Event()
        status = subprocess.check_output(["tailscale", "status", "--json"], timeout=10)
        self.node_id = json.loads(status)["Self"]["ID"]

    def expired(self):
        if self.stopped.is_set() or time.time() >= self.deadline:
            return True
        if self.last_heartbeat is None:
            return time.monotonic() - self.started >= STARTUP_SECONDS
        return time.monotonic() - self.last_heartbeat >= HEARTBEAT_TIMEOUT

    def status(self):
        return {"session_id": self.id, "node_id": self.node_id, "deadline": self.deadline}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def setup(self):
        super().setup()
        self.connection.settimeout(REQUEST_TIMEOUT)

    def log_message(self, *_args):
        pass

    def authenticated(self):
        state = self.server.state
        authorization = self.headers.get("Authorization", "")
        expected = "Bearer " + state.token
        return (hmac.compare_digest(authorization.encode(), expected.encode())
                and self.headers.get("X-Mnsj-Session") == state.id)

    def reply(self, code, body):
        payload = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def authorized(self):
        if not self.authenticated():
            self.reply(403, {"error": "unauthorized"})
            return False
        if self.server.state.expired():
            self.reply(410, {"error": "session expired"})
            return False
        return True

    def do_GET(self):
        if not self.authorized():
            return
        if self.path != "/status":
            self.reply(404, {"error": "not found"})
            return
        self.reply(200, self.server.state.status())

    def do_POST(self):
        if not self.authorized():
            return
        state = self.server.state
        if self.path == "/heartbeat":
            state.last_heartbeat = time.monotonic()
        elif self.path == "/stop":
            state.stopped.set()
        else:
            self.reply(404, {"error": "not found"})
            return
        self.reply(200, state.status())


def main():
    session_id()
    if sys.argv[1:] == ["--validate"]:
        return
    address = os.environ["MNSJ_BIND_ADDRESS"]
    if ipaddress.ip_address(address) not in TAILNET_IPV4:
        raise ValueError("control server must bind a Tailscale IPv4 address")
    state = Session()
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda *_args: state.stopped.set())
    with HTTPServer((address, CONTROL_PORT), Handler) as server:
        server.state = state
        server.timeout = 1
        print("运行器就绪，等待客户端心跳", flush=True)
        while not state.expired():
            server.handle_request()
    print("会话结束，正在注销临时设备", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # 网络异常可能携带授权头，公开日志仅输出固定错误。
        print("运行器控制服务失败，请检查 Secrets、网络和 Actions 权限", file=sys.stderr)
        sys.exit(1)
