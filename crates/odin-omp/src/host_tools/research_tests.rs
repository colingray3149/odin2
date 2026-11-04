use std::cell::RefCell;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::{Arc, Mutex};

use odin_adapter_core::ids::OperationKind;
use serde_json::{json, Value};

use super::*;

/// A stand-in for the root helper: a socket in `dir` that answers each request with the next
/// scripted reply and records what it was asked.
pub(crate) fn helper(dir: &Path, replies: &[Value]) -> (ResearchExit, Arc<Mutex<Vec<Value>>>) {
    let socket = dir.join("exit.sock");
    let listener = UnixListener::bind(&socket).expect("helper socket");
    let asked = Arc::new(Mutex::new(Vec::new()));
    let (log, mut replies) = (Arc::clone(&asked), Vec::from(replies).into_iter());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.expect("connection");
            let mut request = String::new();
            stream.read_to_string(&mut request).expect("request");
            log.lock()
                .unwrap()
                .push(serde_json::from_str(&request).expect("json"));
            let reply = replies
                .next()
                .unwrap_or(json!({"ok": false, "cause": "no reply scripted"}));
            stream
                .write_all(reply.to_string().as_bytes())
                .expect("reply");
        }
    });
    (ResearchExit::new(socket, dir.to_path_buf()), asked)
}

fn moved(region: Option<&str>, tried: &[&str]) -> Value {
    json!({"ok": true, "region": region, "tried": tried})
}

const URL: &str = "https://www.cabotcorp.com/report.pdf";
const TIMEOUT: Duration = Duration::from_secs(150);

#[test]
fn a_refused_fetch_moves_to_the_next_region_and_retries() {
    let dir = tempfile::tempdir().expect("dir");
    let (exit, asked) = helper(dir.path(), &[moved(Some("b"), &["a", "b"])]);
    let mut script = vec![
        Attempt::Done("served"),
        Attempt::Refused("HTTP 403".to_owned()),
    ];
    let mut ways = Vec::new();
    let page = exit.fetch(URL, TIMEOUT, |way, _| {
        ways.push(way);
        script.pop().expect("one attempt per script entry")
    });
    assert_eq!(page, Ok("served"));
    assert_eq!(ways, [Way::Exit, Way::Exit]);
    assert_eq!(
        *asked.lock().unwrap(),
        [json!({"action": "next", "tried": []})]
    );
    assert!(!dir.path().join("refused").exists());
}

#[test]
fn a_site_refused_in_every_region_is_recorded_and_named() {
    let dir = tempfile::tempdir().expect("dir");
    let (exit, asked) = helper(
        dir.path(),
        &[
            moved(Some("b"), &["a", "b"]),
            moved(Some("c"), &["a", "b", "c"]),
            moved(None, &["a", "b", "c"]),
        ],
    );
    let mut attempts = 0;
    let error = exit
        .fetch(URL, TIMEOUT, |_, _| {
            attempts += 1;
            Attempt::<()>::Refused("HTTP 403".to_owned())
        })
        .expect_err("no region served it");
    assert_eq!(attempts, 3, "each region once");
    assert!(
        error.contains("www.cabotcorp.com") && error.contains("a, b, c"),
        "{error}"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("refused/www.cabotcorp.com")).unwrap(),
        "a b c\n"
    );
    let tried: Vec<Value> = asked
        .lock()
        .unwrap()
        .iter()
        .map(|r| r["tried"].clone())
        .collect();
    assert_eq!(
        tried,
        [json!([]), json!(["a", "b"]), json!(["a", "b", "c"])]
    );
}

#[test]
fn an_allowed_host_runs_directly_and_no_other_host_does() {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::create_dir(dir.path().join("direct")).unwrap();
    std::fs::write(dir.path().join("direct/www.cabotcorp.com"), "").unwrap();
    let (exit, asked) = helper(dir.path(), &[moved(None, &["a"])]);
    let mut ways = Vec::new();
    let mut fetch = |url: &str| {
        let _ = exit.fetch(url, TIMEOUT, |way, _| {
            ways.push(way);
            Attempt::<()>::Refused("HTTP 403".to_owned())
        });
    };
    fetch(URL);
    assert!(
        asked.lock().unwrap().is_empty(),
        "a direct fetch never asks the helper"
    );
    // Neither a parent domain nor a sibling host shares the yes.
    fetch("https://cabotcorp.com/report.pdf");
    assert_eq!(ways, [Way::Direct, Way::Exit]);
}

#[test]
fn a_page_that_is_simply_missing_is_returned_as_it_is() {
    let dir = tempfile::tempdir().expect("dir");
    let (exit, asked) = helper(dir.path(), &[]);
    let page = exit.fetch(URL, TIMEOUT, |_, _| {
        Attempt::Done::<Result<(), &str>>(Err("HTTP 404"))
    });
    assert_eq!(page, Ok(Err("HTTP 404")));
    assert!(asked.lock().unwrap().is_empty());
}

#[test]
fn an_exit_that_cannot_move_is_said_so_and_leaves_no_record() {
    let dir = tempfile::tempdir().expect("dir");
    let exit = ResearchExit::new(dir.path().join("missing.sock"), dir.path().to_path_buf());
    let error = exit
        .fetch(URL, TIMEOUT, |_, _| {
            Attempt::<()>::Refused("HTTP 403".to_owned())
        })
        .expect_err("the exit cannot move");
    assert!(
        error.contains("could not move to another region"),
        "{error}"
    );
    assert!(!dir.path().join("refused").exists());
}

#[test]
fn an_adapter_fetch_of_an_allowed_host_runs_the_bridge_with_the_direct_flag_first() {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::create_dir(dir.path().join("direct")).unwrap();
    std::fs::write(dir.path().join("direct/www.cabotcorp.com"), "").unwrap();
    let (exit, asked) = helper(dir.path(), &[]);
    let binding = HandlerBinding::Exec {
        executable: "/carrier".to_owned(),
        argv: vec!["/bridge".to_owned()],
    };
    let request = JsonRpcRequest::new(
        "1",
        RpcMethod::Operation(OperationKind::new("web.read").unwrap()),
        json!({"input": {"url": URL}}),
    )
    .unwrap();
    let seen = RefCell::new(Vec::new());
    let outcome = exit
        .adapter_call(&binding, TIMEOUT, &request, |binding, _, _| {
            seen.borrow_mut().push(binding.clone());
            Ok(JsonRpcOutcome::Success {
                id: "1".to_owned(),
                result: json!({}),
            })
        })
        .expect("answered");
    assert!(matches!(outcome, JsonRpcOutcome::Success { .. }));
    let HandlerBinding::Exec { argv, .. } = &seen.borrow()[0] else {
        panic!("an exec binding");
    };
    assert_eq!(argv, &["--direct", "/bridge"]);
    assert!(asked.lock().unwrap().is_empty());
}
