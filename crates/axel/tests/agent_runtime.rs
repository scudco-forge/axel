//! `axel agent new|edit --runtime`, `axel agent show` and `axel agent ls`, and
//! the runtime a thread's session starts in, through the binary.
use axel_store::{SessionRuntime, Store};
use std::process::{Command, Output};

struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        Self { dir: tempfile::tempdir().unwrap() }
    }
    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_axel"));
        // Harnesses are looked up in `bin` only.
        let path = format!("{}:/usr/bin:/bin", self.dir.path().join("bin").display());
        c.env_clear().env("HOME", self.dir.path()).env("AXEL_HOME", self.dir.path()).env("AXEL_KEYSTORE", "file").env("PATH", path).args(args);
        c
    }
    fn run(&self, args: &[&str]) -> Output {
        self.command(args).output().unwrap()
    }
    fn ok(&self, args: &[&str]) -> String {
        let o = self.run(args);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        String::from_utf8(o.stdout).unwrap()
    }
    /// The runtime on the agent's record.
    fn runtime(&self, agent: &str) -> Option<SessionRuntime> {
        Store::open(&self.dir.path().join("axel.db")).unwrap().agent_by_name(agent).unwrap().unwrap().runtime
    }
    /// The agent's line in `agent ls`, as its columns.
    fn listed(&self, agent: &str) -> Vec<String> {
        let ls = self.ok(&["agent", "ls"]);
        let line = ls.lines().find(|l| l.split_whitespace().next() == Some(agent)).unwrap_or_else(|| panic!("{agent} is not listed: {ls}"));
        line.split_whitespace().map(String::from).collect()
    }
    /// An executable script in the fixture.
    #[cfg(unix)]
    fn script(&self, path: &std::path::Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    /// Run `axel thread new` until it ends (outside Rex a pane's harness
    /// takes over the process, and a managed session is hosted by it): what
    /// Axel said on stderr.
    fn thread_new(&self, agent: &str, extra: &[&str], env: &[(&str, &std::path::Path)]) -> String {
        let mut args = vec!["thread", "new", "fix it", "--agent", agent, "--scratch"];
        args.extend_from_slice(extra);
        let log = self.dir.path().join("thread-new.stderr");
        let mut c = self.command(&args);
        c.envs(env.iter().copied()).stdout(std::process::Stdio::null()).stderr(std::fs::File::create(&log).unwrap());
        let mut child = c.spawn().unwrap();
        let started = std::time::Instant::now();
        while child.try_wait().unwrap().is_none() {
            if started.elapsed() > std::time::Duration::from_secs(30) {
                child.kill().ok();
                panic!("the session did not end");
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        std::fs::read_to_string(&log).unwrap()
    }
}

#[test]
fn the_owner_sets_shows_and_clears_an_agents_runtime() {
    let f = Fixture::new();
    // An agent made without the flag has none: Axel chooses, as before.
    f.ok(&["agent", "new", "alice"]);
    assert_eq!(f.runtime("alice"), None);
    let shown = f.ok(&["agent", "show", "alice"]);
    assert!(shown.contains(r#""runtime": null"#) && !shown.contains("  runtime "), "{shown}");
    assert_eq!(f.listed("alice")[1..6], ["claude", "-", "-", "autopilot", "-"], "harness, model, effort, mode, runtime");

    let created = f.ok(&["agent", "new", "ferro", "omp", "--runtime", "pane"]);
    assert!(created.contains("  runtime pane"), "{created}");
    assert_eq!(f.runtime("ferro"), Some(SessionRuntime::Pane));
    let shown = f.ok(&["agent", "show", "ferro"]);
    assert!(shown.contains(r#""runtime": "pane""#) && shown.contains("  runtime pane"), "{shown}");
    assert_eq!(f.listed("ferro")[1..6], ["omp", "-", "-", "autopilot", "pane"]);

    let edited = f.ok(&["agent", "edit", "alice", "--runtime", "managed"]);
    assert!(edited.contains("  runtime managed"), "{edited}");
    assert_eq!(f.runtime("alice"), Some(SessionRuntime::Managed));

    // Other edits leave it alone, and so does a rename.
    f.ok(&["agent", "edit", "ferro", "--effort", "high", "--runtime-mode", "edits"]);
    f.ok(&["agent", "edit", "ferro", "--name", "ferrum"]);
    assert_eq!(f.runtime("ferrum"), Some(SessionRuntime::Pane));

    // `auto`, or `default` as for `--effort`, lets Axel choose again.
    f.ok(&["agent", "edit", "alice", "--runtime", "auto"]);
    assert_eq!(f.runtime("alice"), None);
    f.ok(&["agent", "edit", "ferrum", "--runtime", "default"]);
    assert_eq!(f.runtime("ferrum"), None);
    assert!(!f.ok(&["agent", "show", "ferrum"]).contains("  runtime "));
}

#[test]
fn an_unknown_runtime_is_refused_when_the_command_is_parsed() {
    let f = Fixture::new();
    f.ok(&["agent", "new", "alice"]);
    for args in [vec!["agent", "edit", "alice", "--runtime", "hologram"], vec!["agent", "new", "zed", "--runtime", "tmux"]] {
        let o = f.run(&args);
        assert_eq!(o.status.code(), Some(2), "a usage error");
        let err = String::from_utf8_lossy(&o.stderr);
        assert!(err.contains("possible values: managed, pane, auto"), "{err}");
    }
    assert_eq!(f.runtime("alice"), None);
    assert!(!f.ok(&["agent", "ls"]).contains("zed"), "nothing was created");
}

#[test]
fn agents_cannot_set_a_runtime() {
    let f = Fixture::new();
    f.ok(&["agent", "new", "alice"]);
    let me = Store::open(&f.dir.path().join("axel.db")).unwrap().agent_by_name("alice").unwrap().unwrap().pubkey;
    for args in [vec!["agent", "edit", "alice", "--runtime", "pane"], vec!["agent", "new", "zed", "--runtime", "pane"]] {
        let o = f.command(&args).env("AXEL_AGENT", &me).output().unwrap();
        assert!(!o.status.success());
        assert!(String::from_utf8_lossy(&o.stderr).contains("owner"));
    }
    assert_eq!(f.runtime("alice"), None);
    assert!(!f.ok(&["agent", "ls"]).contains("zed"));
}

/// Claude's ACP adapter is built into `axel`, so left to itself Axel would
/// host it managed: an agent that defaults to the pane gets its own CLI.
#[cfg(unix)]
#[test]
fn a_thread_starts_in_the_agents_runtime_when_none_is_asked_for() {
    let f = Fixture::new();
    let argv = f.dir.path().join("claude.argv");
    f.script(&f.dir.path().join("bin/claude"), &format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n", argv.display()));
    f.ok(&["agent", "new", "opal", "claude", "--runtime", "pane"]);
    let stderr = f.thread_new("opal", &[], &[]);
    assert!(argv.exists(), "the claude CLI was not started in a pane: {stderr}");
}

/// A stand-in ACP agent: records every request, answers `initialize` and
/// `session/new`, and exits at the first prompt.
#[cfg(unix)]
const ACP_AGENT: &str = r#"#!/bin/sh
while IFS= read -r line; do
  printf '%s\n' "$line" >> "$ACP_RECEIVED"
  id=$(printf '%s' "$line" | sed -n 's/^{"jsonrpc":"2.0","id":\("[^"]*"\).*/\1/p')
  case "$line" in
    *'"method":"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":1,"agentCapabilities":{}}}\n' "$id" ;;
    *'"method":"session/new"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"sessionId":"s1"}}\n' "$id" ;;
    *'"method":"session/prompt"'*) exit 0 ;;
  esac
done
"#;

#[cfg(unix)]
#[test]
fn the_runtime_asked_for_on_the_thread_beats_the_agents() {
    let f = Fixture::new();
    let harness = f.dir.path().join("acp-agent");
    f.script(&harness, ACP_AGENT);
    let received = f.dir.path().join("acp.received");
    f.ok(&["agent", "new", "gus", harness.to_str().unwrap(), "--runtime", "pane"]);
    let stderr = f.thread_new("gus", &["--runtime", "managed"], &[("ACP_RECEIVED", received.as_path())]);
    let requests = std::fs::read_to_string(&received).unwrap_or_else(|e| panic!("the session was not hosted over ACP ({e}): {stderr}"));
    assert!(requests.contains(r#""method":"session/prompt""#), "the managed session ran: {requests}");
}
