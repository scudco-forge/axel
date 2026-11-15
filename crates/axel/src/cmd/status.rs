//! Status for harnesses without hooks: `axel status STATE [MSG]`, which an
//! agent or a script reports itself, and `axel session watch`, which follows
//! the OSC 7501 program status a harness reports by itself
//! ([`axel_store::Harness::status_app`]) through Rex, never its screen.

use std::io::BufRead;

use anyhow::{Context, Result};
use axel_identity::Keypair;
use axel_rex::osc;
use axel_store::{BlockedKind, Session, SessionState, SessionUpdate, StatusReport, Store};
use serde_json::Value;

use super::{Ctx, convert};

/// `axel status` and the MCP `set_status` tool.
pub fn run(state: &str, msg: Option<&str>, kind: Option<&str>) -> Result<()> {
    // `clear` is an OSC-only state (it removes the tab indicator) and records as idle.
    let osc_state = osc::State::parse(state)
        .with_context(|| format!("unknown state {state:?}; use idle|working|done|blocked|error|clear"))?;
    let kind: Option<BlockedKind> = kind
        .map(|k| k.parse().map_err(|_| anyhow::anyhow!("unknown kind {k:?}; use permission|question|auth")))
        .transpose()?;
    let app = std::env::var("AXEL_AGENT_NAME").ok();
    let _ = osc::emit_to_tty(&osc::Report {
        state: osc_state,
        id: None,
        kind: kind.map(convert::osc_kind),
        progress: None,
        app: app.as_deref(),
        title: None,
        msg,
    });

    if let (Ok(session_id), Ok(agent_pk)) = (std::env::var("AXEL_SESSION"), std::env::var("AXEL_AGENT")) {
        let ctx = Ctx::open()?;
        let Some(session) = ctx.store.get_session(&session_id)? else { return Ok(()) };
        let Ok(kp) = ctx.agent_signer(&agent_pk, Some(&session.thread_id)) else { return Ok(()) };
        record(&ctx.store, &kp, &session_id, osc_state, kind, msg)?;
    }
    Ok(())
}

/// Record `state` as the session's status, and the session state it means
/// (`error` leaves that alone).
fn record(store: &Store, signer: &Keypair, session_id: &str, state: osc::State, kind: Option<BlockedKind>, msg: Option<&str>) -> Result<()> {
    store.record_status(
        signer,
        session_id,
        &StatusReport { state: convert::status_state(state), kind, title: None, msg: msg.map(String::from), progress: None },
    )?;
    let ss = match state {
        osc::State::Working => Some(SessionState::Running),
        osc::State::Blocked => Some(SessionState::Blocked),
        osc::State::Done | osc::State::Idle | osc::State::Clear => Some(SessionState::Idle),
        osc::State::Error => None,
    };
    if let Some(ss) = ss {
        store.update_session(signer, session_id, &SessionUpdate { state: Some(ss), ..Default::default() })?;
    }
    Ok(())
}

/// What a harness says of itself in a block's program status.
#[derive(Debug, PartialEq, Eq)]
struct Reported {
    state: osc::State,
    kind: Option<BlockedKind>,
    msg: Option<String>,
}

/// What `app` reports in a block's `program_status` result
/// (`{"records": [...]}`): its root record (no `id`) when it has one, else
/// the most urgent of its records.  Records of any other app, Axel's own
/// mirror (`app=axel`) among them, don't count.
fn reported(records: &Value, app: &str) -> Option<Reported> {
    let parse = |r: &Value| -> Option<Reported> {
        let state = osc::State::parse(r.get("state")?.as_str()?)?;
        Some(Reported {
            state,
            kind: r.get("kind").and_then(Value::as_str).and_then(osc::Kind::parse).map(convert::blocked_kind),
            msg: r.get("msg").and_then(Value::as_str).filter(|m| !m.is_empty()).map(String::from),
        })
    };
    let mine: Vec<(bool, Reported)> = records
        .get("records")?
        .as_array()?
        .iter()
        .filter(|r| r.get("app").and_then(Value::as_str) == Some(app))
        .filter_map(|r| Some((r.get("id").and_then(Value::as_str).unwrap_or("").is_empty(), parse(r)?)))
        .collect();
    let root = mine.iter().position(|(root, _)| *root);
    let pick = root.or_else(|| (0..mine.len()).max_by_key(|&i| convert::status_state(mine[i].1.state).urgency()))?;
    mine.into_iter().nth(pick).map(|(_, r)| r)
}

/// Bring a pane session's status in line with what its harness reports of
/// itself in `records`, its block's `program_status`.  When the harness
/// reports nothing, `cleared` says whether it took its report back (`clear`,
/// recorded as idle) rather than having said nothing yet.  Writes only when
/// the state (or what it's blocked on) changes, so a harness reporting
/// progress costs nothing.  A paused session keeps its state: its harness is
/// frozen, so its records are stale.  Whether it wrote.
pub(super) fn follow(store: &Store, signer: &Keypair, session: &Session, records: &Value, cleared: bool) -> Result<bool> {
    let Some(app) = session.harness.status_app().filter(|_| session.state != SessionState::Paused) else { return Ok(false) };
    let Some(r) = reported(records, app).or_else(|| cleared.then_some(Reported { state: osc::State::Clear, kind: None, msg: None })) else {
        return Ok(false);
    };
    let now = store.status(&session.id)?;
    if now.is_some_and(|s| s.state == convert::status_state(r.state) && s.kind == r.kind) {
        return Ok(false);
    }
    record(store, signer, &session.id, r.state, r.kind, r.msg.as_deref())?;
    Ok(true)
}

/// What a `rex events --json` line says about a block.
#[derive(Debug, PartialEq, Eq)]
enum BlockEvent {
    /// Its program status changed; `removed`: records were cleared.
    Status { removed: bool },
    /// Its program exited, or it closed.
    Gone,
}

fn block_event(line: &str, block: &str) -> Option<BlockEvent> {
    let v: Value = serde_json::from_str(line).ok()?;
    if v.get("type").and_then(Value::as_str) != Some("session_event") {
        return None;
    }
    let event = v.get("payload")?.get("event")?;
    let payload = event.get("payload")?;
    if payload.get("block_id").and_then(Value::as_str) != Some(block) {
        return None;
    }
    match (event.get("type")?.as_str()?, payload.get("name").and_then(Value::as_str)) {
        ("block_closed", _) | ("block_event", Some("child_exited")) => Some(BlockEvent::Gone),
        ("block_event", Some("program_status_changed")) => Some(BlockEvent::Status { removed: false }),
        ("block_event", Some("program_status_removed")) => Some(BlockEvent::Status { removed: true }),
        _ => None,
    }
}

/// `axel session watch SESSION`: [`follow`] a pane session's harness for as
/// long as its pane lives.  The launcher starts it in the background for a
/// harness with a [`axel_store::Harness::status_app`]; it listens to
/// `rex events` and reads the block's records again on each change of them.
pub fn watch(session_id: &str) -> Result<()> {
    let ctx = Ctx::open()?;
    let rex = ctx.rex.as_ref().context("not inside Rex")?;
    let session = ctx.store.get_session(session_id)?.with_context(|| format!("no session {session_id}"))?;
    anyhow::ensure!(session.harness.status_app().is_some(), "{} reports no program status of its own", session.harness);
    anyhow::ensure!(session.rex_session_id.as_deref() == Some(rex.env().session.as_str()), "the session's pane is in another Rex session");
    let block = session.rex_block_id.clone().context("the session has no pane")?;
    let signer = ctx.agent_signer(&session.agent_pubkey, Some(&session.thread_id))?;
    // Listen first, then catch up on what the harness reported before.
    let mut events = rex.events_command().spawn().context("starting rex events")?;
    let stdout = events.stdout.take().context("rex events has no output")?;
    let sync = |session: &Session, cleared: bool| match rex.program_status(&block) {
        Ok(records) => follow(&ctx.store, &signer, session, &records, cleared).map(|_| ()),
        Err(e) => {
            eprintln!("axel: {e}");
            Ok(())
        }
    };
    sync(&session, false)?;
    for line in std::io::BufReader::new(stdout).lines().map_while(Result::ok) {
        let cleared = match block_event(&line, &block) {
            Some(BlockEvent::Status { removed }) => removed,
            Some(BlockEvent::Gone) => break,
            None => continue,
        };
        let Some(session) = ctx.store.get_session(session_id)?.filter(|s| s.state != SessionState::Ended) else { break };
        sync(&session, cleared)?;
    }
    let _ = events.kill();
    let _ = events.wait();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axel_identity::{Keystore, attest};
    use axel_store::{Harness, NewAgent, NewSession, RuntimeMode, SessionRuntime, StatusState};
    use serde_json::json;

    /// A live omp pane session, just launched: running, its status `working`.
    fn omp_pane(ctx: &Ctx) -> (Keypair, Session) {
        let owner = ctx.owner().unwrap();
        let key = Keypair::generate();
        ctx.store
            .insert_agent(&NewAgent {
                pubkey: key.public().to_base58(),
                name: "ferro".into(),
                harness: Harness::Omp,
                model: None,
                effort: None,
                skills: vec![],
                prompt: None,
                color: None,
                runtime_mode: RuntimeMode::default(),
                runtime: None,
                auth_tag: Some(attest(&owner, &key.public(), "").unwrap().to_tag()),
            })
            .unwrap();
        let thread = ctx.store.create_thread(&owner, "port the parser", "port the parser", None).unwrap();
        let environment = ctx.store.local_environment().unwrap();
        let session = ctx
            .store
            .start_session(
                &key,
                &NewSession {
                    thread_id: thread.id,
                    agent_pubkey: key.public().to_base58(),
                    environment_id: environment.id,
                    environment_label: environment.label,
                    project_repo_key: None,
                    harness: Harness::Omp,
                    runtime_mode: RuntimeMode::default(),
                    resumed_from: None,
                    runtime: SessionRuntime::Pane,
                },
            )
            .unwrap();
        record(&ctx.store, &key, &session.id, osc::State::Working, None, Some("starting")).unwrap();
        (key, session)
    }

    fn ctx() -> (tempfile::TempDir, Ctx) {
        let temp = tempfile::tempdir().unwrap();
        let ctx = Ctx { store: Store::open_memory().unwrap(), keystore: Keystore::open_at(temp.path().join("keys.json"), false).unwrap(), rex: None };
        (temp, ctx)
    }

    fn states(ctx: &Ctx, session: &Session) -> (StatusState, SessionState) {
        let status = ctx.store.status(&session.id).unwrap().unwrap().state;
        (status, ctx.store.get_session(&session.id).unwrap().unwrap().state)
    }

    #[test]
    fn a_pane_session_follows_what_its_harness_reports_in_program_status() {
        let (_temp, ctx) = ctx();
        let (key, session) = omp_pane(&ctx);
        let done = json!({"records": [{"state": "done", "app": "omp", "effective_app": "omp", "msg": "parser ported"}]});
        assert!(follow(&ctx.store, &key, &session, &done, false).unwrap());
        assert_eq!(states(&ctx, &session), (StatusState::Done, SessionState::Idle));
        assert_eq!(ctx.store.status(&session.id).unwrap().unwrap().msg.as_deref(), Some("parser ported"));

        let working = json!({"records": [{"state": "working", "app": "omp"}]});
        assert!(follow(&ctx.store, &key, &session, &working, false).unwrap());
        assert_eq!(states(&ctx, &session), (StatusState::Working, SessionState::Running));
        // The same state again (progress, a new message) writes nothing.
        assert!(!follow(&ctx.store, &key, &session, &json!({"records": [{"state": "working", "app": "omp", "msg": "tests"}]}), false).unwrap());

        let asking = json!({"records": [{"state": "blocked", "kind": "question", "app": "omp", "msg": "which DB?"}]});
        assert!(follow(&ctx.store, &key, &session, &asking, false).unwrap());
        assert_eq!(states(&ctx, &session), (StatusState::Blocked, SessionState::Blocked));
        assert_eq!(ctx.store.status(&session.id).unwrap().unwrap().kind, Some(BlockedKind::Question));

        let idle = json!({"records": [{"state": "idle", "app": "omp"}]});
        assert!(follow(&ctx.store, &key, &session, &idle, false).unwrap());
        assert_eq!(states(&ctx, &session), (StatusState::Idle, SessionState::Idle));
    }

    #[test]
    fn nothing_reported_changes_nothing_until_the_harness_clears_its_report() {
        let (_temp, ctx) = ctx();
        let (key, session) = omp_pane(&ctx);
        let none = json!({"records": []});
        assert!(!follow(&ctx.store, &key, &session, &none, false).unwrap());
        assert_eq!(states(&ctx, &session), (StatusState::Working, SessionState::Running));
        assert!(follow(&ctx.store, &key, &session, &none, true).unwrap());
        assert_eq!(states(&ctx, &session), (StatusState::Idle, SessionState::Idle));
    }

    #[test]
    fn only_the_harness_own_records_count() {
        let (_temp, ctx) = ctx();
        let (key, session) = omp_pane(&ctx);
        // Axel's mirror and other programs say done; omp has said nothing.
        let others = json!({"records": [{"state": "done", "app": "axel"}, {"state": "done", "app": "ferro"}]});
        assert!(!follow(&ctx.store, &key, &session, &others, false).unwrap());
        assert_eq!(states(&ctx, &session), (StatusState::Working, SessionState::Running));
        let done = json!({"records": [{"state": "done", "app": "omp"}]});
        // A paused harness is frozen: what it last said is stale.
        let paused = Session { state: SessionState::Paused, ..session.clone() };
        assert!(!follow(&ctx.store, &key, &paused, &done, false).unwrap());
        // A harness without a status app of its own is never followed.
        let claude = Session { harness: Harness::Claude, ..session };
        assert!(!follow(&ctx.store, &key, &claude, &done, false).unwrap());
        assert_eq!(ctx.store.status(&claude.id).unwrap().unwrap().state, StatusState::Working);
    }

    #[test]
    fn the_root_record_speaks_for_the_harness_else_its_most_urgent_one() {
        let records = json!({"records": [
            {"id": "sub", "state": "blocked", "kind": "permission", "app": "omp"},
            {"state": "working", "app": "omp"},
            {"state": "done", "app": "axel"},
        ]});
        assert_eq!(reported(&records, "omp").unwrap().state, osc::State::Working);
        let children = json!({"records": [
            {"id": "a", "state": "done", "app": "omp"},
            {"id": "b", "state": "blocked", "kind": "permission", "app": "omp"},
        ]});
        assert_eq!(reported(&children, "omp"), Some(Reported { state: osc::State::Blocked, kind: Some(BlockedKind::Permission), msg: None }));
        assert_eq!(reported(&json!({"records": [{"state": "bogus", "app": "omp"}]}), "omp"), None);
        assert_eq!(reported(&Value::Null, "omp"), None);
    }

    #[test]
    fn rex_events_about_the_block_are_status_changes_or_its_end() {
        let block = "block:1";
        let event = |ty: &str, payload: Value| json!({"type": "session_event", "payload": {"session_id": "session:1", "event": {"type": ty, "payload": payload}}}).to_string();
        let terminal = |name: &str, block: &str| event("block_event", json!({"block_id": block, "creator_name": "com.superlogical.terminal", "name": name, "payload": {}}));
        assert_eq!(block_event(&terminal("program_status_changed", block), block), Some(BlockEvent::Status { removed: false }));
        assert_eq!(block_event(&terminal("program_status_removed", block), block), Some(BlockEvent::Status { removed: true }));
        assert_eq!(block_event(&terminal("child_exited", block), block), Some(BlockEvent::Gone));
        assert_eq!(block_event(&event("block_closed", json!({"block_id": block})), block), Some(BlockEvent::Gone));
        assert_eq!(block_event(&terminal("program_status_changed", "block:2"), block), None);
        assert_eq!(block_event(&terminal("title_changed", block), block), None);
        assert_eq!(block_event("not json", block), None);
    }
}
