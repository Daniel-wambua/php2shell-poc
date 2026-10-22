#!/usr/bin/env python3
"""
php2shell-checker — Python port of https://github.com/openai/php2shell-checker
Authorized defensive use only: checks *version disclosure* to classify
a PHP install/URL as vulnerable/ok/unknown. No exploit is performed.

Exit codes match the reference implementation:
  0 = OK, 1 = VULNERABLE, 3 = UNKNOWN, 2 = invalid args

Usage:
  python3 phpcheck.py "https://example.com" [--timeout SECONDS] [--json]
  python3 phpcheck.py --local [--php PATH] [--json]
  python3 phpcheck.py --scan FILE [--timeout SECONDS] [--json]
  python3 phpcheck.py --version
"""
import argparse
import http.client
import json
import re
import ssl
import subprocess
import sys
import urllib.parse

VERSION = "1.0.0"
VULNERABLE_THROUGH = {
    "5.4": 45, "5.5": 38, "5.6": 40,
    "7.0": 33, "7.1": 33, "7.2": 34, "7.3": 33, "7.4": 33,
    "8.0": 30, "8.1": 34, "8.2": 34, "8.3": 35, "8.4": 26, "8.5": 11,
}
USAGE = "Usage: phpcheck.py URL [--timeout SECONDS] [--json]\n       phpcheck.py --local [--php PATH] [--json]\n       phpcheck.py --scan FILE [--timeout SECONDS] [--json]\n       phpcheck.py --version"

PATCH_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)([-+~].*)?$")
DEV_RE = re.compile(r"(?:^|[-+~.])(?:dev|alpha|beta|rc)", re.IGNORECASE)
LOCAL_RE = re.compile(r"^PHP ([0-9][^\s,;)]*)", re.MULTILINE)
URL_RE = re.compile(r"\bPHP[/ ]([^\s,;)]+)", re.IGNORECASE)


def patch_status(version: str | None) -> str:
    if not version:
        return "unknown"
    m = PATCH_RE.match(version)
    if not m:
        return "unknown"
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    suffix = m.group(4) or ""
    key = f"{major}.{minor}"
    cutoff = VULNERABLE_THROUGH.get(key)
    if cutoff is None:
        return "unknown"
    if patch <= cutoff:
        return "vulnerable"
    if DEV_RE.search(suffix):
        return "unknown"
    return "ok"


def fetch_headers(address: str, timeout: float) -> str:
    if any(ord(c) <= 0x20 or ord(c) == 0x7f for c in address):
        raise ValueError("URL contains spaces or control characters")
    parsed = urllib.parse.urlparse(address)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Use an http:// or https:// URL")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("URL credentials and fragments are not supported")
    if not parsed.hostname:
        raise ValueError("Invalid URL")

    host = parsed.hostname
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    headers_acc: list[str] = []
    for method in ("HEAD", "GET"):
        conn = None
        try:
            if parsed.scheme == "https":
                ctx = ssl.create_default_context()
                conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
            conn.request(method, path, headers={
                "Host": host,
                "Connection": "close",
                "User-Agent": f"php2shell-checker/{VERSION}",
            })
            resp = conn.getresponse()
            server = resp.getheader("Server") or resp.getheader("server") or ""
            powered = resp.getheader("X-Powered-By") or resp.getheader("x-powered-by") or ""
            if not server:
                for k, v in resp.getheaders():
                    if k.lower() == "server":
                        server = v
                        break
            if not powered:
                for k, v in resp.getheaders():
                    if k.lower() == "x-powered-by":
                        powered = v
                        break
            headers_acc.append(server)
            headers_acc.append(powered)
            try:
                resp.read()
            except Exception:
                pass
            status = resp.status
            conn.close()
            if status not in (405, 501):
                break
        except Exception as e:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
            msg = str(e)
            low = msg.lower()
            if "timed out" in low or "timeout" in low or "timedout" in low:
                raise TimeoutError(f"timeout: {msg}") from e
            raise
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
    return "\n".join(headers_acc)


def classify_text(text: str, is_local: bool) -> tuple[str | None, str]:
    pattern = LOCAL_RE if is_local else URL_RE
    version = None
    status = "unknown"
    for m in pattern.finditer(text):
        cand = m.group(1)
        cand_status = patch_status(cand)
        if version is None or cand_status == "vulnerable" or status == "ok":
            version = cand
            status = cand_status
        if status == "vulnerable":
            break
    return version, status


def local_php_output(php_bin: str) -> str:
    try:
        result = subprocess.run(
            [php_bin, "-v"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        text = (result.stdout or "") + (result.stderr or "")
        if result.returncode != 0 and not text.strip():
            raise RuntimeError(f"php -v failed: return code {result.returncode}")
        return text
    except subprocess.TimeoutExpired as e:
        raise TimeoutError(f"timeout: {e}") from e
    except FileNotFoundError as e:
        raise RuntimeError(str(e)) from e


def check_target(target: str, timeout: float) -> dict:
    version = None
    error = None
    status = "unknown"
    try:
        text = fetch_headers(target, timeout)
        version, status = classify_text(text, False)
    except Exception as exc:
        error = str(exc)

    exit_code = {"ok": 0, "vulnerable": 1, "unknown": 3}[status]
    reason = error if error else (f"PHP {version}" if version else "PHP version not found")
    return {
        "target": target,
        "patch_status": status,
        "php_version": version,
        "reason": reason,
        "exit_code": exit_code,
    }


def run_scan(list_path: str, timeout: float, json_mode: bool) -> None:
    from concurrent.futures import ThreadPoolExecutor

    try:
        with open(list_path, "r", encoding="utf-8") as f:
            raw = f.read()
    except OSError as exc:
        print(f"cannot read scan list {list_path}: {exc}", file=sys.stderr)
        sys.exit(2)

    targets = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("http://") or line.startswith("https://"):
            targets.append(line)
        else:
            targets.append("https://" + line)

    if not targets:
        print(f"scan list {list_path} contains no targets", file=sys.stderr)
        sys.exit(2)

    with ThreadPoolExecutor(max_workers=min(16, len(targets))) as pool:
        results = list(pool.map(lambda t: check_target(t, timeout), targets))

    vulnerable = sum(1 for r in results if r["patch_status"] == "vulnerable")
    ok = sum(1 for r in results if r["patch_status"] == "ok")
    unknown = sum(1 for r in results if r["patch_status"] == "unknown")
    report = {
        "total": len(results),
        "vulnerable": vulnerable,
        "ok": ok,
        "unknown": unknown,
        "results": results,
    }

    if json_mode:
        print(json.dumps(report, indent=2))
    else:
        for r in results:
            label = {"ok": "OK        ", "vulnerable": "VULNERABLE", "unknown": "UNKNOWN   "}[r["patch_status"]]
            print(f"{label}  {r['target']:<45} {r['reason']}")
        print()
        print(f"{report['total']} targets: {vulnerable} vulnerable, {ok} ok, {unknown} unknown")

    if vulnerable:
        sys.exit(1)
    if unknown:
        sys.exit(3)
    sys.exit(0)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phpcheck.py",
        usage=USAGE,
        add_help=False,
        description="Check a website or local PHP binary to see if it's vulnerable to php2shell (authorized homelab use)",
    )
    p.add_argument("url", nargs="?", help="URL to check (http:// or https://)")
    p.add_argument("--local", action="store_true", help="Check local PHP binary instead of a URL")
    p.add_argument("--scan", metavar="FILE", help="Scan newline-separated target list (one URL/host per line)")
    p.add_argument("--php", default="php", help="Path to PHP binary for --local (default: php)")
    p.add_argument("--timeout", default="10", help="Request timeout in seconds (default 10, max 60) — URL mode only")
    p.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    p.add_argument("--version", action="store_true", help="Print version and exit")
    p.add_argument("-h", "--help", action="store_true", dest="help", help="Print help and exit")
    return p


def main() -> None:
    parser = build_parser()
    args, unknown = parser.parse_known_args()
    if unknown:
        print(f"Provide a URL or --local, not both\n{USAGE}", file=sys.stderr)
        sys.exit(2)

    if args.help:
        print(USAGE)
        sys.exit(0)
    if args.version:
        print(VERSION)
        sys.exit(0)

    has_url = args.url is not None
    modes = sum([bool(args.local), bool(args.scan), bool(has_url)])
    if modes != 1:
        print(f"Provide a URL or --local or --scan, not more than one\n{USAGE}", file=sys.stderr)
        sys.exit(2)

    try:
        t = float(args.timeout)
    except ValueError:
        print(f"--timeout must be greater than 0 and at most 60 seconds\n{USAGE}", file=sys.stderr)
        sys.exit(2)
    if not args.local and not (t > 0 and t <= 60):
        print(f"--timeout must be greater than 0 and at most 60 seconds\n{USAGE}", file=sys.stderr)
        sys.exit(2)

    if args.scan:
        run_scan(args.scan, t, args.json)

    version = None
    error = None
    status = "unknown"

    try:
        if args.local:
            text = local_php_output(args.php)
            version, status = classify_text(text, True)
        else:
            text = fetch_headers(args.url, t)
            version, status = classify_text(text, False)
    except Exception as exc:
        error = str(exc)

    code = {"ok": 0, "vulnerable": 1, "unknown": 3}[status]
    reason = error if error else (f"PHP {version}" if version else "PHP version not found")
    report = {
        "patch_status": status,
        "php_version": version,
        "reason": reason,
        "exit_code": code,
    }
    if args.json:
        print(json.dumps(report, separators=(",", ":")))
    else:
        print(f"{status.upper()}: {reason}")
    sys.exit(code)


if __name__ == "__main__":
    main()
