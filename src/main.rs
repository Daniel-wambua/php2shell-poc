use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::time::Duration;

use clap::Parser;
use regex::Regex;
use serde::Serialize;
use std::sync::OnceLock;
use url::Url;

const VERSION: &str = "1.0.0";

fn vulnerable_map() -> &'static HashMap<&'static str, u32> {
    static MAP: OnceLock<HashMap<&'static str, u32>> = OnceLock::new();
    MAP.get_or_init(|| {
        HashMap::from([
            ("5.4", 45),
            ("5.5", 38),
            ("5.6", 40),
            ("7.0", 33),
            ("7.1", 33),
            ("7.2", 34),
            ("7.3", 33),
            ("7.4", 33),
            ("8.0", 30),
            ("8.1", 34),
            ("8.2", 34),
            ("8.3", 35),
            ("8.4", 26),
            ("8.5", 11),
        ])
    })
}

fn patch_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(\d+)\.(\d+)\.(\d+)([-+~].*)?$").unwrap())
}

fn dev_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)(?:^|[-+~.])(?:dev|alpha|beta|rc)").unwrap())
}

fn local_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^PHP ([0-9][^\s,;)]*)").unwrap())
}

fn url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\bPHP[/ ]([^\s,;)]+)").unwrap())
}

const USAGE: &str = "Usage: php2shell-checker URL [--timeout SECONDS] [--json]\n       php2shell-checker --local [--php PATH] [--json]\n       php2shell-checker --scan FILE [--timeout SECONDS] [--json]\n       php2shell-checker --version";

#[derive(Parser, Debug)]
#[command(
    name = "php2shell-checker",
    version = VERSION,
    about = "Check a website or local PHP binary to see if it's vulnerable to php2shell (authorized homelab use)",
    override_usage = USAGE,
    disable_help_flag = true,
    disable_version_flag = true
)]
struct Args {
    #[arg(value_name = "URL")]
    url: Option<String>,

    #[arg(long)]
    local: bool,

    #[arg(long, value_name = "FILE")]
    scan: Option<String>,

    #[arg(long, default_value = "php")]
    php: String,

    #[arg(long, default_value = "10")]
    timeout: String,

    #[arg(long)]
    json: bool,

    #[arg(long)]
    version: bool,

    #[arg(long, short = 'h')]
    help: bool,
}

#[derive(Serialize)]
struct Report {
    patch_status: String,
    php_version: Option<String>,
    reason: String,
    exit_code: i32,
}

#[derive(Serialize, Clone)]
struct ScanEntry {
    target: String,
    patch_status: String,
    php_version: Option<String>,
    reason: String,
    exit_code: i32,
}

#[derive(Serialize)]
struct ScanReport {
    total: usize,
    vulnerable: usize,
    ok: usize,
    unknown: usize,
    results: Vec<ScanEntry>,
}

fn patch_status(version: Option<&str>) -> &'static str {
    let v = match version {
        Some(s) => s,
        None => return "unknown",
    };
    let caps = match patch_re().captures(v) {
        Some(c) => c,
        None => return "unknown",
    };
    let major: u32 = caps[1].parse().unwrap_or(0);
    let minor: u32 = caps[2].parse().unwrap_or(0);
    let patch: u32 = caps[3].parse().unwrap_or(0);
    let suffix = caps.get(4).map(|m| m.as_str()).unwrap_or("");

    let key = format!("{}.{}", major, minor);
    let cutoff = match vulnerable_map().get(key.as_str()) {
        Some(c) => *c,
        None => return "unknown",
    };
    if patch <= cutoff {
        return "vulnerable";
    }
    if dev_re().is_match(suffix) {
        return "unknown";
    }
    "ok"
}

fn fetch_headers(address: &str, timeout_secs: f64) -> Result<String, String> {
    if address.chars().any(|c| c <= '\u{0020}' || c == '\u{007f}') {
        return Err("URL contains spaces or control characters".to_string());
    }
    let url = Url::parse(address).map_err(|e| e.to_string())?;
    if !["http", "https"].contains(&url.scheme()) {
        return Err("Use an http:// or https:// URL".to_string());
    }
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err("URL credentials and fragments are not supported".to_string());
    }

    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_millis((timeout_secs * 1000.0).ceil() as u64))
        .build()
        .map_err(|e| e.to_string())?;

    let mut headers_acc = Vec::new();

    for method in ["HEAD", "GET"] {
        let req = if method == "HEAD" {
            client.head(url.clone())
        } else {
            client.get(url.clone())
        };
        let resp = req.send().map_err(|e| {
            let s = e.to_string();
            if s.to_lowercase().contains("timed out")
                || s.to_lowercase().contains("timeout")
                || e.is_timeout()
            {
                format!("timeout: {}", s)
            } else {
                s
            }
        })?;
        let status = resp.status().as_u16();
        let server = {
            let mut vals: Vec<String> = Vec::new();
            for (k, v) in resp.headers().iter() {
                if k.as_str().eq_ignore_ascii_case("server") {
                    if let Ok(s) = v.to_str() {
                        vals.push(s.to_string());
                    }
                }
            }
            if vals.is_empty() {
                String::new()
            } else {
                vals.join(", ")
            }
        };
        let powered = {
            let mut vals: Vec<String> = Vec::new();
            for (k, v) in resp.headers().iter() {
                if k.as_str().eq_ignore_ascii_case("x-powered-by") {
                    if let Ok(s) = v.to_str() {
                        vals.push(s.to_string());
                    }
                }
            }
            if vals.is_empty() {
                String::new()
            } else {
                vals.join(", ")
            }
        };
        headers_acc.push(server);
        headers_acc.push(powered);
        if ![405, 501].contains(&status) {
            break;
        }
    }

    Ok(headers_acc.join("\n"))
}

fn classify_text(text: &str, is_local: bool) -> (Option<String>, String) {
    let re = if is_local { local_re() } else { url_re() };

    let mut version: Option<String> = None;
    let mut status = "unknown".to_string();

    for caps in re.captures_iter(text) {
        let cand = caps[1].to_string();
        let cand_status = patch_status(Some(&cand));
        let should_update = version.is_none() || cand_status == "vulnerable" || status == "ok";
        if should_update {
            version = Some(cand);
            status = cand_status.to_string();
        }
        if status == "vulnerable" {
            break;
        }
    }
    (version, status)
}

fn local_php_output(php_bin: &str) -> Result<String, String> {
    let out = Command::new(php_bin)
        .arg("-v")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| e.to_string())?;
    let mut text = String::from_utf8_lossy(&out.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    if !out.status.success() && text.trim().is_empty() {
        return Err(format!("php -v failed: {}", out.status));
    }
    Ok(text)
}

fn main() {
    let args = Args::parse();

    if args.help {
        println!("{}", USAGE);
        std::process::exit(0);
    }
    if args.version {
        println!("{}", VERSION);
        std::process::exit(0);
    }

    let modes = [args.local, args.scan.is_some(), args.url.is_some()]
        .iter()
        .filter(|b| **b)
        .count();
    if modes != 1 {
        eprintln!("Provide a URL or --local or --scan, not more than one\n{}", USAGE);
        std::process::exit(2);
    }

    let timeout: f64 = match args.timeout.parse() {
        Ok(v) => v,
        Err(_) => {
            eprintln!("--timeout must be greater than 0 and at most 60 seconds\n{}", USAGE);
            std::process::exit(2);
        }
    };
    if !args.local && !(timeout > 0.0 && timeout <= 60.0) {
        eprintln!("--timeout must be greater than 0 and at most 60 seconds\n{}", USAGE);
        std::process::exit(2);
    }

    if let Some(list_path) = args.scan.as_deref() {
        run_scan(list_path, timeout, args.json);
    }

    let mut version: Option<String> = None;
    let mut error: Option<String> = None;
    let mut status = "unknown".to_string();

    if args.local {
        match local_php_output(&args.php) {
            Ok(text) => {
                let (v, s) = classify_text(&text, true);
                version = v;
                status = s;
            }
            Err(e) => {
                error = Some(e);
            }
        }
    } else {
        let addr = args.url.unwrap();
        match fetch_headers(&addr, timeout) {
            Ok(text) => {
                let (v, s) = classify_text(&text, false);
                version = v;
                status = s;
            }
            Err(e) => {
                error = Some(e);
            }
        }
    }

    let code: i32 = match status.as_str() {
        "ok" => 0,
        "vulnerable" => 1,
        _ => 3,
    };
    let reason = if let Some(e) = error {
        e
    } else if let Some(v) = version.clone() {
        format!("PHP {}", v)
    } else {
        "PHP version not found".to_string()
    };

    let report = Report {
        patch_status: status.clone(),
        php_version: version.clone(),
        reason: reason.clone(),
        exit_code: code,
    };

    if args.json {
        println!("{}", serde_json::to_string(&report).unwrap());
    } else {
        println!("{}: {}", status.to_uppercase(), reason);
    }
    std::process::exit(code);
}

fn check_target(target: &str, timeout: f64) -> ScanEntry {
    let mut version: Option<String> = None;
    let mut error: Option<String> = None;
    let mut status = "unknown".to_string();

    match fetch_headers(target, timeout) {
        Ok(text) => {
            let (v, s) = classify_text(&text, false);
            version = v;
            status = s;
        }
        Err(e) => error = Some(e),
    }

    let exit_code: i32 = match status.as_str() {
        "ok" => 0,
        "vulnerable" => 1,
        _ => 3,
    };
    let reason = if let Some(e) = error {
        e
    } else if let Some(v) = version.clone() {
        format!("PHP {}", v)
    } else {
        "PHP version not found".to_string()
    };

    ScanEntry {
        target: target.to_string(),
        patch_status: status,
        php_version: version,
        reason,
        exit_code,
    }
}

fn run_scan(list_path: &str, timeout: f64, json: bool) -> ! {
    let raw = match std::fs::read_to_string(list_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cannot read scan list {}: {}", list_path, e);
            std::process::exit(2);
        }
    };

    let targets: Vec<String> = raw
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            if l.starts_with("http://") || l.starts_with("https://") {
                l.to_string()
            } else {
                format!("https://{}", l)
            }
        })
        .collect();

    if targets.is_empty() {
        eprintln!("scan list {} contains no targets", list_path);
        std::process::exit(2);
    }

    let results: Vec<ScanEntry> = std::thread::scope(|scope| {
        let handles: Vec<_> = targets
            .iter()
            .map(|t| scope.spawn(move || check_target(t, timeout)))
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("scan worker panicked"))
            .collect()
    });

    let vulnerable = results.iter().filter(|r| r.patch_status == "vulnerable").count();
    let ok = results.iter().filter(|r| r.patch_status == "ok").count();
    let unknown = results.iter().filter(|r| r.patch_status == "unknown").count();

    let total = results.len();
    let report = ScanReport {
        total,
        vulnerable,
        ok,
        unknown,
        results,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        for r in &report.results {
            let label = match r.patch_status.as_str() {
                "ok" => "OK        ",
                "vulnerable" => "VULNERABLE",
                _ => "UNKNOWN   ",
            };
            println!("{}  {:<45} {}", label, r.target, r.reason);
        }
        println!();
        println!(
            "{} targets: {} vulnerable, {} ok, {} unknown",
            report.total, report.vulnerable, report.ok, report.unknown
        );
    }

    if vulnerable > 0 {
        std::process::exit(1);
    }
    if unknown > 0 {
        std::process::exit(3);
    }
    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_status_boundaries() {
        let cases = [
            ("5.4.45", "vulnerable"),
            ("5.5.38", "vulnerable"),
            ("5.6.40", "vulnerable"),
            ("7.0.33", "vulnerable"),
            ("7.1.33", "vulnerable"),
            ("7.2.34", "vulnerable"),
            ("7.3.33", "vulnerable"),
            ("7.4.33", "vulnerable"),
            ("8.0.30", "vulnerable"),
            ("8.1.34", "vulnerable"),
            ("8.2.34", "vulnerable"),
            ("8.3.35", "vulnerable"),
            ("8.4.26", "vulnerable"),
            ("8.5.11", "vulnerable"),
            ("5.4.46", "ok"),
            ("8.4.27", "ok"),
            ("8.5.12", "ok"),
            ("8.4.100", "ok"),
            ("8.4.27-1+ubuntu24.04.1+deb.sury.org+1", "ok"),
            ("8.4.27-1ubuntu1", "ok"),
            ("8.4.26-1ubuntu1", "vulnerable"),
        ];
        for (v, expected) in cases {
            assert_eq!(patch_status(Some(v)), expected, "{}", v);
        }
    }

    #[test]
    fn patch_status_unknown() {
        for v in [
            "8.4.27RC1",
            "8.4.27-rc1",
            "8.4.27~beta1",
            "8.4",
            "not-a-version",
            "9.0.0",
            "8.6.0",
        ] {
            assert_eq!(patch_status(Some(v)), "unknown", "{}", v);
        }
        assert_eq!(patch_status(None), "unknown");
    }

    #[test]
    fn classify_local() {
        let text = "PHP 8.4.27 (cli) (NTS)\nCopyright (c) The PHP Group\nZend Engine v4.4.27\n";
        let (v, s) = classify_text(text, true);
        assert_eq!(v.unwrap(), "8.4.27");
        assert_eq!(s, "ok");

        let text2 = "Warning: PHP Startup: Unable to load dynamic library redis\nPHP 8.4.27 (cli) (NTS)\nCopyright (c) The PHP Group\n";
        let (v2, s2) = classify_text(text2, true);
        assert_eq!(v2.unwrap(), "8.4.27");
        assert_eq!(s2, "ok");
    }

    #[test]
    fn classify_url_conflicting() {
        let text = "Apache/2.4.62 PHP/8.4.26\nPHP/8.4.27";
        let (v, s) = classify_text(text, false);
        assert_eq!(s, "vulnerable");
        assert_eq!(v.unwrap(), "8.4.26");

        let text2 = "Apache/2.4.62 PHP/9.0.0\nPHP/8.4.27";
        let (v2, s2) = classify_text(text2, false);
        assert_eq!(s2, "unknown");
        assert_eq!(v2.unwrap(), "9.0.0");
    }
}
