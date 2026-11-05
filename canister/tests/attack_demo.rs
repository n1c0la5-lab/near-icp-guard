//! The attack demo's requests against the real policy code, without a network
//! or a model: the same `agent/demo/scenarios.json` the demo uses. If a rule
//! stops refusing what the demo shows it refusing, this goes red in CI.

use candid::Principal;
use guard::policy::{Guard, Policy};
use serde::Deserialize;

#[derive(Deserialize)]
struct File {
    policy: Policy,
    scenarios: Vec<Scenario>,
}

#[derive(Deserialize)]
struct Scenario {
    id: String,
    expected_reason: Option<String>,
    scripted: Vec<Step>,
}

#[derive(Deserialize)]
struct Step {
    tool: String,
    receiver: Option<String>,
    yocto: Option<String>,
    recipient: Option<String>,
    message: Option<String>,
    expect: String,
}

const NOW: u64 = 1_793_629_521_000_000_000;

fn owner() -> Principal {
    Principal::from_slice(&[1])
}
fn agent() -> Principal {
    Principal::from_slice(&[2])
}

fn file() -> File {
    serde_json::from_str(include_str!("../../agent/demo/scenarios.json")).unwrap()
}

/// A fresh guard per scenario, as the demo reinstalls the canister per run.
fn guard(policy: &Policy) -> Guard {
    let mut g = Guard::new(owner()).unwrap();
    g.set_agent(owner(), Some(agent())).unwrap();
    g.set_policy(owner(), policy).unwrap();
    g
}

/// Runs one step to the end. `Ok(())` if signed, `Err(reason)` if refused.
fn replay(g: &mut Guard, step: &Step) -> Result<(), String> {
    match step.tool.as_str() {
        "request_payment" => {
            let t = g
                .begin_sign(agent(), step.receiver.as_ref().unwrap(), step.yocto.as_ref().unwrap(), NOW)
                .map_err(|r| r.to_string())?;
            g.finish_sign(t, Ok("tx".to_string()));
        }
        "request_message_signature" => {
            let t = g
                .begin_message(agent(), step.message.as_ref().unwrap(), &[7; 32], step.recipient.as_ref().unwrap(), None, NOW)
                .map_err(|r| r.to_string())?;
            g.finish_message(t, Ok("hash".to_string()));
        }
        other => panic!("unknown tool {other}"),
    }
    Ok(())
}

#[test]
fn every_demo_request_gets_the_expected_answer() {
    let file = file();
    let mut refused = 0;
    let mut signed = 0;
    for s in &file.scenarios {
        let mut g = guard(&file.policy);
        for (i, step) in s.scripted.iter().enumerate() {
            match (replay(&mut g, step), step.expect.as_str()) {
                (Ok(()), "signed") => signed += 1,
                (Err(reason), "refused") => {
                    let want = s.expected_reason.as_deref().expect("a refused step needs expected_reason");
                    assert!(reason.contains(want), "{} step {i}: refused for the wrong reason: {reason}", s.id);
                    refused += 1;
                }
                (got, want) => panic!("{} step {i}: wanted {want}, got {got:?}", s.id),
            }
        }
    }
    // The file must keep exercising both answers.
    assert!(refused >= 6, "only {refused} refusals");
    assert!(signed >= 4, "only {signed} signatures");
}

#[test]
fn each_attack_scenario_exists_and_is_refused_at_least_once() {
    let file = file();
    for id in ["outside-allowlist", "outside-allowlist-plausible", "over-limit", "split-daily-limit", "nep413-intents"] {
        let s = file.scenarios.iter().find(|s| s.id == id).unwrap_or_else(|| panic!("scenario {id} is gone"));
        assert!(s.scripted.iter().any(|t| t.expect == "refused"), "{id} refuses nothing");
    }
    for id in ["control-payment", "control-message"] {
        let s = file.scenarios.iter().find(|s| s.id == id).unwrap_or_else(|| panic!("scenario {id} is gone"));
        assert!(s.scripted.iter().all(|t| t.expect == "signed"), "{id} is not a clean control");
    }
}

#[test]
fn the_attack_listed_for_nep413_stays_refused_even_if_the_owner_lists_it() {
    // `set_policy` refuses the list, so the rule does not depend on the list's content.
    let mut policy = file().policy;
    policy.nep413_recipients = Some(vec!["intents.near".to_string()]);
    let mut g = Guard::new(owner()).unwrap();
    assert!(g.set_policy(owner(), &policy).is_err());
}
