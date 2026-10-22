<div align="center">

# CVE-2026-109618 / CVE-2026-109619 — php2shell PoC

### PHP Session Upload Progress RCE — Checker & Exploit PoC (Rust + Python)

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Rust](https://img.shields.io/badge/Rust-2021-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CVE](https://img.shields.io/badge/CVE-2026--109618%20%7C%202026--109619-red.svg)](https://github.com/Daniel-wambua/php2shell-poc)
[![Severity](https://img.shields.io/badge/Severity-Critical%209.2-critical.svg)](https://github.com/Daniel-wambua/php2shell-poc)

**Authorized-use only. For owned infrastructure and lab environments.**

</div>

---


Two tools for the **php2shell** advisories, both authorized-use only and aimed
at owned infrastructure:

This repo contains the **`php2shell-poc`** — a lab exploit PoC that demonstrates
what an attacker does with the vulnerable surface, and doubles as proof that a
fix worked.

## The vulnerabilities

| CVE | GHSA | Summary | Fixed in |
| --- | --- | --- | --- |
| CVE-2026-109618 | GHSA-w8hw-w9fx-j79w | RCE via OOM corruption | 8.2.35, 8.3.36, 8.4.27, 8.5.12 |
| CVE-2026-109619 | GHSA-6wmf-4rv5-p3rp | RCE via stale global state across requests | 8.2.35, 8.3.36, 8.4.27, 8.5.12 |

Both are CVSS 9.2 critical. Upstream fix is php-src commit `3584a98bda`
("Avoid state corruption via bailout"): replace the OOM bailout with
`UnwindExit` and reset globals reachable during request startup.

Exposure comes from `session.upload_progress` (enabled by default since
PHP 5.4), which writes attacker-influenced request data — including multipart
filenames — into the session store during request startup, before application
code runs.

---

## Why this exists

- a **native Rust binary** (no Node runtime needed on the host),
- a **drop-in Python port** for environments without a Rust toolchain,
- an additional **`--scan` mode** to check many self-hosted sites in one pass,
- a parity test harness that asserts both ports match the reference behavior.

---

## Technology stack

| Component | Version / Crate | Purpose |
| --- | --- | --- |
| Rust | edition 2021, `rustc >= 1.75` | Native binary |
| `clap` | 4 | CLI parsing |
| `regex` | 1 | Version/banner parsing |
| `serde`, `serde_json` | 1 | JSON report output |
| `reqwest` (rustls) | 0.12 | HTTP client, no OpenSSL dependency |
| `url` | 2 | URL validation |
| Python | `>= 3.10` (stdlib only) | Portable fallback port |

---

## Directory topology

```
.
├── Cargo.toml                  # Rust manifest (two binaries)
├── src/bin/poc.rs              # php2shell-poc (Rust) + unit tests
├── php2shell_poc.py            # php2shell-poc (Python, stdlib only)
├── tests/
│   └── test_php2shell_poc.py   # 14 Python unit tests for the PoC
├── hosts.example.txt           # Sample scan list for --scan
├── lab/
│   ├── docker-compose.yml      # Vulnerable PHP 8.4.26 mod_php target
│   ├── php.ini                 # Vulnerable config matching PoC requirements
│   └── webroot/
│       ├── index.php           # Session endpoint (injection target)
│       └── vuln.php            # Deliberate LFI sink (chain terminator)
├── README.md
└── backupcode_coding-high/     # Timestamped backups of edited sources
```

---

## Build and run

### Rust

Builds one binary: `php2shell-poc`.

```sh
cargo build --release
./target/release/php2shell-poc --help
```

### Python

Stdlib-only — no `pip install` required.

```sh
python3 php2shell_poc.py --help     # PoC
```

---

## Usage

### PoC usage

Rust binary and Python script are interchangeable — same flags, same exit codes.

```sh
# Confirm RCE against the lab target
./target/release/php2shell-poc --target http://127.0.0.1:8088/index.php \
    --lfi-path /vuln.php --session-path /tmp --command 'id'

python3 php2shell_poc.py --target http://127.0.0.1:8088/index.php \
    --lfi-path /vuln.php --session-path /tmp --command 'id'

# Machine-readable proof
python3 php2shell_poc.py --target http://127.0.0.1:8088/index.php \
    --command 'whoami' --json
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--target` | required | URL of any endpoint that starts a session |
| `--inject-path` | `/index.php` | Endpoint that receives the upload |
| `--lfi-path` | `/vuln.php` | Include sink that reads the session file |
| `--session-path` | `/tmp` | Target `session.save_path` |
| `--command` | `id` | System command to run |
| `--attempts` | `3` | Retry count |
| `--timeout` | `10.0` | Per-request socket timeout (max 120) |
| `--sid` | random | Fixed session id |
| `--json` | off | Structured output |

### Scan list format

```
# Blank lines and lines starting with '#' are ignored.
# Bare hosts get an https:// prefix; full URLs are used as-is.
wiki.lab.local
https://git.lab.local
http://10.0.0.5:8080
```

A ready-to-edit template lives in `hosts.example.txt`.

---

## Result semantics

| Result | Exit code | Meaning |
| --- | --- | --- |
| `OK` | `0` | Stable patch above the cutoff for a listed branch. |
| `VULNERABLE` | `1` | Patch at or below the cutoff for that branch. |
| `UNKNOWN` | `3` | No version found, unlisted branch, or a prerelease/dev build. |
| invalid args | `2` | Bad flags, bad mutually-exclusive mode, or unusable timeout. |

For `--scan`, the exit code is the worst result across all targets:
`1` if any target is vulnerable, else `3` if any is unknown, else `0`.

JSON schema (single target):

```json
{"patch_status":"vulnerable","php_version":"8.4.26","reason":"PHP 8.4.26","exit_code":1}
```

JSON schema (`--scan`):

```json
{
  "total": 3,
  "vulnerable": 1,
  "ok": 1,
  "unknown": 1,
  "results": [
    {"target":"http://10.0.0.5/","patch_status":"ok","php_version":"8.4.27","reason":"PHP 8.4.27","exit_code":0}
  ]
}
```

---

## Detection logic (must match the reference exactly)

1. **Fetch.** Send `HEAD`; retry with `GET` only if the response is `405` or `501`.
   Redirects are never followed. All `Server` and `X-Powered-By` header values
   are collected and newline-joined.
2. **Extract.**
   - URL mode: `\bPHP[ /]([^\s,;)]+)` (case-insensitive).
   - Local mode: `^PHP (\d[^\s,;)]*)` (multiline, from `php -v`).
3. **Classify** each candidate with the cutoff table:

   | Branch | Vulnerable through |
   | --- | --- |
   | 5.4 | 5.4.45 |
   | 5.5 | 5.5.38 |
   | 5.6 | 5.6.40 |
   | 7.0 / 7.1 | .33 / .33 |
   | 7.2 | 7.2.34 |
   | 7.3 / 7.4 | .33 / .33 |
   | 8.0 | 8.0.30 |
   | 8.1 / 8.2 | .34 / .34 |
   | 8.3 | 8.3.35 |
   | 8.4 | 8.4.26 |
   | 8.5 | 8.5.11 |

   - `patch <= cutoff` → `vulnerable`.
   - `patch > cutoff` **and** a `dev|alpha|beta|rc` suffix → `unknown`
     (a prerelease is not evidence of a stable fix).
   - Suffixes such as `-1ubuntu1` or `-1+deb.sury.org+1` are ignored for the
     patch comparison and do not downgrade an `ok`.
   - Unlisted major/minor → `unknown`.
4. **Precedence.** A `vulnerable` candidate always wins and short-circuits. An
   `unknown` candidate is never overwritten by a later `ok`; an `ok` candidate
   may be replaced by a later `vulnerable`.

---

## The PoC: how the attack actually works

`php2shell-poc` demonstrates the **session-injection primitive** that makes
php2shell dangerous, chained into an application sink. This is the realistic
attacker path against a typical homelab stack (WordPress, Laravel, custom PHP
with any `include`), and it is fully verifiable end to end.

### Attack chain

1. **Session fixation.** The attacker picks a `PHPSESSID` value and submits it
   as a multipart *form field*. `session.use_only_cookies = 0` (a common
   default-leaning setting) makes PHP accept it, so the attacker knows the
   exact session filename: `/tmp/sess_<sid>`.
2. **Filename injection.** A multipart POST carries the reserved field
   `PHP_SESSION_UPLOAD_PROGRESS`. Because `session.upload_progress` is enabled,
   PHP's request-startup handler records upload metadata — including the
   attacker-controlled `filename` — into the session store *before any
   application code executes*. PHP code lands on disk inside the session file.
3. **Include.** Any LFI-style sink (`include($_GET['page'])`) reads the session
   file, and attacker PHP executes with the web server's privileges.

Command output is wrapped in `___START___`/`___END___` markers so the PoC can
prove execution by parsing the HTTP response, not by guessing.

### Prerequisites (this is why it is not universal)

| Requirement | Typical homelab status |
| --- | --- |
| `session.upload_progress.enabled = On` | On by default |
| PHP accepts a session id from the POST body (`session.use_only_cookies = 0`) | Often on; off on hardened builds |
| An include/LFI sink in the app | Only some apps |
| Known session save path | Usually `/tmp` or `/var/lib/php/sessions` |

No LFI sink means no RCE through this path. That is a real constraint, not a
formality — it is what separates a defensible homelab from a compromised one.

### Running it

```sh
./target/release/php2shell-poc \
    --target http://127.0.0.1:8088/index.php \
    --lfi-path /vuln.php \
    --session-path /tmp \
    --command 'id'
```

Flags: `--inject-path`, `--lfi-path`, `--session-path`, `--command`,
`--attempts`, `--timeout`, `--sid`, `--json`.

Exit codes: `0` RCE confirmed, `1` not confirmed, `2` usage/network error.

---

## Lab

`lab/` is a self-contained, deliberately vulnerable target:

```sh
cd lab && docker compose up -d
curl -sI http://127.0.0.1:8088/index.php | grep -i powered
```

The image is `php:8.4.26-apache`. `php.ini` sets the conditions the PoC needs:
`session.upload_progress.enabled = On`, `session.use_only_cookies = 0`,
`session.save_path = /tmp`, `memory_limit = 8M`, and `max_input_vars = 5000`.
`webroot/vuln.php` is the intentional LFI sink.

Two lab details matter and are easy to miss when reproducing this elsewhere:

- **`max_input_vars`** must exceed the number of multipart fields the reference
  chain primes with. At `max_input_vars = 1000`, PHP emits
  `Input variables exceeded 1000` during request startup and aborts before the
  session initializes, so nothing works.
- **Single prefork worker.** The stock image runs `StartServers 5` /
  `MaxRequestWorkers 150`, so consecutive requests land on different workers and
  heap state never persists. `lab/mpm_prefork.conf` pins
  `ServerLimit 1` / `StartServers 1` / `MaxRequestWorkers 1`.

Note that patching PHP alone does not stop this chain: 8.4.27 still records the
attacker-supplied filename into the session file. Remediation requires
`session.use_only_cookies = On` and removing the include sink — see the
remediation section above.

Tear down with `cd lab && docker compose down`.

---

## Verification

```sh
cargo test                              # 5 unit tests, 0 warnings
cargo build --release
python3 -m unittest tests.test_php2shell_poc -v   # 14 Python PoC tests
```

**Checker:** a 66-case parity harness covers local version parsing,
startup-warning tolerance, all 14 branch boundaries (vulnerable and +1 patch),
prerelease and unlisted-branch handling, distribution suffixes, `Server` vs
`X-Powered-By`, conflicting banners, HEAD→GET fallback, missing headers,
no-PHP-in-body, plain-text output, and every argument-validation path. Both
implementations pass 66/66.

**PoC (Rust):** 5 unit tests cover marker detection, negative responses, session
path construction, multipart shape, and query encoding.

**PoC (Python):** 14 unit tests cover marker extraction (single and multiline),
no-marker responses, session path construction, multipart wire shape, payload
quote escaping, status-code parsing, body partitioning, SID uniqueness, an
end-to-end confirmed run, an end-to-end negative run, and all three error paths
(unreachable host, bad scheme, invalid timeout).

Both implementations verified live against the lab:

```
$ python3 php2shell_poc.py --target http://127.0.0.1:8088/index.php \
      --lfi-path /vuln.php --command 'id'
[*] attempt 1: planted sid=php2shellpoc01de9329... status=200 bytes=323
[*] attempt 1: lfi status=200
RCE CONFIRMED: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Negative control (wrong LFI path) returns `NOT CONFIRMED` with exit `1` on both.

**Privilege reality:** commands run as the web server user (`www-data` in this
lab). The injection primitive cannot elevate to root — that is a separate
post-exploitation concern on the host, not a property of this vulnerability.

---

## Operating notes for a homelab

- Hosts can hide or rewrite `X-Powered-By` in `php.ini`
  (`expose_php = Off`). That yields `UNKNOWN` — it does *not* mean patched.
- The version in headers may reflect a distro backport that already carries the
  fix. Confirm against the official PHP security release and your distro's
  changelog before treating `VULNERABLE` as conclusive.
- Point `--scan` only at hosts you own or administer. Keep the sites offline
  until the affected hosts report `OK`.
- Prefer `--json` for feeding results into monitoring or a rerun diff after
  patch upgrades.

### Remediation order

1. **Patch PHP** to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or newer. This is the
   only complete fix — the OOM corruption lives in the Zend engine.
2. **Disable upload progress** as a stopgap on EOL branches that will never get
   a patch: `session.upload_progress.enabled = Off`. In FPM pools use
   `php_admin_flag[session.upload_progress.enabled] = off` so apps cannot
   re-enable it.
3. **Set `session.use_only_cookies = On`** so a POST-body `PHPSESSID` cannot
   fixate the session. This breaks the injection step above outright.
4. **Remove LFI sinks.** No user-controlled value should reach `include`,
   `require`, `fopen`, or `readfile` without an allowlist.
5. **Re-verify** with both tools: the PoC must
   say `NOT CONFIRMED`.

### Detection signals

A successful run of this attack leaves: `POST` requests carrying
`PHP_SESSION_UPLOAD_PROGRESS`, session files containing PHP tags, and PHP worker
processes spawning `sh`/`id`/`whoami`. Alert on any of those in web logs.

---

## License and provenance

Behavior, cutoff table, and CLI semantics mirror
