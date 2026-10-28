//! Agent cases for key storage: where the agent creates each key, the policy that chooses it ([contract] §5.7), the metadata that reports it (§3.1), and the records that name it ([agent intent]).
//!
//! The policy reaches the agent through the mock's key storage control, so every case here runs on the mock only.
//! A case that needs two available key storages runs on Windows, where the Windows software provider and the file backend both are.
//!
//! [contract]: ../../../docs/agent-identity/CONTRACT.agent-identity.md#key-storage
//! [agent intent]: ../../agent-identity/INTENT.md#key-storage

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context as _, ensure};
use serde_json::{Value, json};

use super::{
    AgentCase, POLL, WAIT, current_thumbprint, dropped_enrollment, is_error_level_log_line, key_exists, key_name,
    new_token, slot_key_exists, until_renewal_settled, with_agent,
};
use crate::Context;
use crate::client::{Target, Token, count, expect_status, field};
use crate::key_storage::{self, FILE, UNLISTED, WINDOWS_SOFTWARE_PROVIDER, builtin_default};

/// How long a case watches the agent hold back a renewal or start none.
///
/// It exceeds the retry backoff cap that every case sets, so the agent checks its policy again at least once meanwhile.
const HOLD_OBSERVATION: Duration = Duration::from_secs(3);

/// How long a case watches an agent that must leave an identity, or all of them, unused.
const PAUSE_OBSERVATION: Duration = Duration::from_secs(5);

/// The log files the agent writes in its case directory.
const LOG_FILES: [&str; 2] = ["agent-stdout.log", "agent-stderr.log"];

/// A required policy that no agent can satisfy, since its only name is outside the contract's table.
fn holding_policy() -> Value {
    json!({ "backends": [UNLISTED], "required": true })
}

/// Sets the key storage policy in the effective config of every identity on the mock, or removes it when `policy` is `None`.
async fn set_policy(target: &Target, policy: Option<&Value>) -> anyhow::Result<()> {
    let body = policy.map_or_else(|| json!({ "clear": true }), |policy| json!({ "policy": policy }));
    expect_status(&target.control("key-storage", &body).await?, 200)
}

/// Waits until the agent stores a config whose `key_storage` member is `policy`, or has none when `policy` is `None`, and returns the stored identity.
async fn until_policy_stored(
    case: &mut AgentCase,
    target: &Target,
    authority: &str,
    identity_id: &str,
    policy: Option<&Value>,
) -> anyhow::Result<Value> {
    case.until_state(
        target,
        authority,
        identity_id,
        "the config with the new key storage policy",
        |state| state["config"].get("key_storage") == policy,
    )
    .await
}

/// Requests a renewal and waits until the agent completes it, then checks that the new current key is in `expected` and returns the stored identity.
async fn renewed_into(
    case: &mut AgentCase,
    target: &Target,
    authority: &str,
    identity_id: &str,
    expected: &str,
) -> anyhow::Result<Value> {
    let old_key = key_name(&case.state(authority)?, "current")?.to_owned();
    target.management().request_renewal(identity_id).await?;
    settled_into(case, target, authority, identity_id, &old_key, expected).await
}

/// Waits until a renewal that replaces `old_key` settles, then checks that the new current key is in `expected` and returns the stored identity.
async fn settled_into(
    case: &mut AgentCase,
    target: &Target,
    authority: &str,
    identity_id: &str,
    old_key: &str,
    expected: &str,
) -> anyhow::Result<Value> {
    let state = until_renewal_settled(case, target, authority, identity_id, old_key).await?;
    ensure!(
        state["keys"]["current"]["key_storage"] == expected,
        "the agent created the new key in {} instead of {expected}",
        state["keys"]["current"]["key_storage"]
    );
    ensure!(
        slot_key_exists(case, &state, "current")?,
        "the new current key is missing from the key storage its slot records"
    );
    Ok(state)
}

/// Fails if a renew request reaches the authority or the identity's keys change while [`HOLD_OBSERVATION`] elapses.
async fn assert_no_renewal(case: &mut AgentCase, target: &Target, authority: &str, why: &str) -> anyhow::Result<()> {
    let renews = count(&target.requests(None).await?, "renew")?;
    let keys = case.state(authority)?["keys"].clone();
    let started = Instant::now();
    while started.elapsed() < HOLD_OBSERVATION {
        tokio::time::sleep(POLL).await;
        case.check_running()?;
        ensure!(
            count(&target.requests(None).await?, "renew")? == renews,
            "the agent sent a renew request although {why}"
        );
        ensure!(
            case.state(authority)?["keys"] == keys,
            "the agent changed the identity's keys although {why}"
        );
    }
    Ok(())
}

/// The signed requests an authority has received: renew, confirm, check-in and channel connect.
async fn signed_requests(target: &Target) -> anyhow::Result<[u64; 4]> {
    let requests = target.requests(None).await?;
    Ok([
        count(&requests, "renew")?,
        count(&requests, "confirm")?,
        count(&requests, "check_in")?,
        count(&requests, "connect")?,
    ])
}

/// The enroll attempts for `token`, including those a retry barrier answers.
async fn enroll_attempts(target: &Target, token: &Token) -> anyhow::Result<u64> {
    let requests = target.requests(Some(token)).await?;
    Ok(count(&requests, "enroll")? + count(&requests, "enroll_retry_503")?)
}

/// Waits until `target` authenticates a stream for the `before`-th time or later, which shows that an identity of the agent signs again.
async fn until_authenticated_connect(
    case: &mut AgentCase,
    target: &Target,
    before: u64,
    what: &str,
) -> anyhow::Result<()> {
    poll!(case, WAIT, POLL, format!("{what} authenticated no new stream"), async {
        Ok((count(&target.requests(None).await?, "authenticated_connects")? > before).then_some(()))
    });
    Ok(())
}

/// Rewrites a file of the agent's in place, so that it keeps the owner and permissions the agent gave it, and returns the bytes it now holds.
fn rewrite_in_place(path: &Path, contents: &[u8]) -> anyhow::Result<Vec<u8>> {
    use std::io::Write as _;

    let mut file = std::fs::OpenOptions::new().write(true).truncate(true).open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(contents.to_vec())
}

/// Applies `edit` to the JSON file at `path` in place, as an administrator's hand edit, and returns the bytes it now holds.
fn edit_json_in_place(path: &Path, edit: impl FnOnce(&mut Value)) -> anyhow::Result<Vec<u8>> {
    let mut value: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    edit(&mut value);
    rewrite_in_place(path, &serde_json::to_vec_pretty(&value)?)
}

/// The current length of each of the agent's log files, so that a later check reads only what the agent logs afterwards.
fn log_mark(case: &AgentCase) -> anyhow::Result<[u64; 2]> {
    let mut mark = [0; 2];
    for (length, name) in mark.iter_mut().zip(LOG_FILES) {
        match std::fs::metadata(case.path().join(name)) {
            Ok(metadata) => *length = metadata.len(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(mark)
}

/// Waits until the agent logs an error-level line after `mark`.
async fn until_error_logged(case: &mut AgentCase, mark: [u64; 2], what: &str) -> anyhow::Result<()> {
    poll!(
        case,
        WAIT,
        POLL,
        format!("the agent logged no error for {what}"),
        async {
            for (start, name) in mark.into_iter().zip(LOG_FILES) {
                let contents = std::fs::read(case.path().join(name)).unwrap_or_default();
                let start = usize::try_from(start)?.min(contents.len());
                if String::from_utf8_lossy(&contents[start..])
                    .lines()
                    .any(is_error_level_log_line)
                {
                    return Ok(Some(()));
                }
            }
            Ok(None)
        }
    );
    Ok(())
}

/// A key storage a policy can prefer over the built-in default: the file backend on Windows, where it is available too, and an unlisted name elsewhere, where the suite knows of no second available key storage.
const fn preferred_alternative() -> &'static str {
    if cfg!(windows) { FILE } else { UNLISTED }
}

/// Every enrollment key is in the built-in default, even when the authority's policy prefers another key storage, since the policy arrives only with the enrollment response.
pub(crate) async fn a_key_storage_enrollment_key_in_builtin_default(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-metadata
    // oracle: intent crates/agent-identity/INTENT.md §Key storage
    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        let policy = json!({ "backends": [preferred_alternative()], "required": false });
        set_policy(&target, Some(&policy)).await?;
        let token = new_token(case, 1).await?;
        let (id, key) = dropped_enrollment(case, &token).await?;
        let progress = case.in_progress()?.context("the in-progress record disappeared")?;
        ensure!(
            progress["key_storage"] == builtin_default(),
            "the in-progress record names {} for the enrollment key instead of {}",
            progress["key_storage"],
            builtin_default()
        );
        expect_status(
            &target
                .control("retry-barrier", &json!({ "endpoint": "enroll", "pause": false }))
                .await?,
            200,
        )?;
        let (enrolled, state) = case.enrolled(&target, &token).await?;
        ensure!(
            enrolled == id
                && state["keys"]["current"]["key_name"] == key.as_str()
                && state["keys"]["current"]["key_storage"] == builtin_default(),
            "the identity's current key is not its enrollment key in {}",
            builtin_default()
        );
        ensure!(
            state["config"]["key_storage"] == policy,
            "the agent did not store the enrollment config's policy as received"
        );
        let record = case.identity_record(&target, &id).await?;
        ensure!(
            record.metadata_value("key_storage") == Some(builtin_default()),
            "the agent reports key_storage {:?} for a key in {}",
            record.metadata_value("key_storage"),
            builtin_default()
        );
        Ok(())
    })
    .await
}

/// Each new key goes to the first available key storage the policy lists, while each existing key keeps opening from the storage its slot records, across a restart that finds the identity's keys in two storages.
///
/// The policy is added, then removed, through config updates; the metadata of each renew and `Hello` reports the storage of the key that the CSR carries or that signs.
pub(crate) async fn a_key_storage_policy_selects_each_new_key_storage(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-metadata
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    // oracle: intent crates/agent-identity/INTENT.md §Identities
    // oracle: intent crates/agent-identity/INTENT.md §Key storage
    with_agent(ctx, None, false, async move |case| {
        case.set_identity_debug("min_renewal_interval_secs", json!(0))?;
        case.start().await?;
        let target = case.ctx.target.clone();
        let (id, state) = case.enroll_new(&target, 1).await?;
        let authority = field(&state, "authority_id")?.to_owned();
        let enrollment_key = key_name(&state, "current")?.to_owned();
        case.until_identity(&target, &id, "a working channel", |record| record.connected)
            .await?;
        let record = case.identity_record(&target, &id).await?;
        let available = record.metadata_value("key_storage_available").unwrap_or_default();
        ensure!(
            key_storage::available_names(available)?.contains(&FILE),
            "the agent reports key_storage_available {available:?} without the file backend"
        );

        let policy = json!({ "backends": [UNLISTED, FILE, WINDOWS_SOFTWARE_PROVIDER], "required": false });
        set_policy(&target, Some(&policy)).await?;
        until_policy_stored(case, &target, &authority, &id, Some(&policy)).await?;
        let renews = count(&target.requests(None).await?, "renew")?;
        expect_status(
            &target
                .control("retry-barrier", &json!({ "endpoint": "renew", "pause": true }))
                .await?,
            200,
        )?;
        target.faults(&json!({ "drop_next_response": "renew" })).await?;
        target.management().request_renewal(&id).await?;
        let pending = case
            .until_state(
                &target,
                &authority,
                &id,
                "a pending key for the held renewal",
                |state| state["keys"]["pending"]["key_name"].is_string(),
            )
            .await?;
        ensure!(
            pending["keys"]["pending"]["key_storage"] == FILE
                && pending["keys"]["current"]["key_storage"] == WINDOWS_SOFTWARE_PROVIDER,
            "the renewal did not put the new key in the first available listed storage beside the current key: {}",
            pending["keys"]
        );
        let pending_key = key_name(&pending, "pending")?.to_owned();
        poll!(
            case,
            WAIT,
            POLL,
            "the held renew request never reached the authority",
            async { Ok((count(&target.requests(None).await?, "renew")? > renews).then_some(())) }
        );
        case.until_identity(&target, &id, "renew metadata", |record| {
            record.metadata_value("key_storage") == Some(FILE)
        })
        .await
        .context("renew metadata does not report the key storage of the key its CSR carries")?;

        case.stop().await?;
        case.start().await?;
        case.until_identity(
            &target,
            &id,
            "a Hello signed by the current key after restart",
            |record| record.connected && record.metadata_value("key_storage") == Some(WINDOWS_SOFTWARE_PROVIDER),
        )
        .await?;
        expect_status(
            &target
                .control("retry-barrier", &json!({ "endpoint": "renew", "pause": false }))
                .await?,
            200,
        )?;
        let settled = settled_into(case, &target, &authority, &id, &enrollment_key, FILE).await?;
        ensure!(
            key_name(&settled, "current")? == pending_key,
            "the agent did not complete the renewal with the pending key it had recorded in the file backend"
        );
        case.until_identity(&target, &id, "a Hello signed by the file key", |record| {
            record.connected && record.metadata_value("key_storage") == Some(FILE)
        })
        .await?;

        set_policy(&target, None).await?;
        until_policy_stored(case, &target, &authority, &id, None).await?;
        renewed_into(case, &target, &authority, &id, builtin_default()).await?;
        Ok(())
    })
    .await
}

/// A policy whose listed storages are all unavailable and that isn't required lets the agent create the new key in its built-in default.
///
/// It differs from [`a_key_storage_required_policy_holds_requested_renewal`]'s policy only in `required`.
pub(crate) async fn a_key_storage_unavailable_preference_uses_builtin_default(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
    // oracle: intent crates/agent-identity/INTENT.md §Key storage
    with_agent(ctx, None, false, async move |case| {
        case.set_identity_debug("min_renewal_interval_secs", json!(0))?;
        case.start().await?;
        let target = case.ctx.target.clone();
        set_policy(&target, Some(&json!({ "backends": [UNLISTED], "required": false }))).await?;
        let (id, state) = case.enroll_new(&target, 1).await?;
        let authority = field(&state, "authority_id")?.to_owned();
        renewed_into(case, &target, &authority, &id, builtin_default()).await?;
        Ok(())
    })
    .await
}

/// While a required policy lists no available key storage, a renewal that `RenewRequested` starts sends no renew request and keeps the current key and stream, until a config without the policy releases it.
pub(crate) async fn a_key_storage_required_policy_holds_requested_renewal(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    // oracle: intent crates/agent-identity/INTENT.md §Key storage
    with_agent(ctx, None, false, async move |case| {
        case.set_identity_debug("min_renewal_interval_secs", json!(0))?;
        case.start().await?;
        let target = case.ctx.target.clone();
        set_policy(&target, Some(&holding_policy())).await?;
        let (id, state) = case.enroll_new(&target, 1).await?;
        let authority = field(&state, "authority_id")?.to_owned();
        let before = case
            .until_identity(&target, &id, "a working channel", |record| record.connected)
            .await?;
        target.management().request_renewal(&id).await?;
        assert_no_renewal(
            case,
            &target,
            &authority,
            "its required policy lists no available key storage",
        )
        .await?;
        let held = case.identity_record(&target, &id).await?;
        ensure!(
            held.connected && held.renewal_requested && current_thumbprint(&held)? == current_thumbprint(&before)?,
            "the agent dropped its stream or certificate while holding its renewal back"
        );
        set_policy(&target, None).await?;
        settled_into(
            case,
            &target,
            &authority,
            &id,
            key_name(&state, "current")?,
            builtin_default(),
        )
        .await?;
        Ok(())
    })
    .await
}

/// While a required policy lists no available key storage, a renewal that check-in's `renewal_requested` starts sends no renew request and keeps checking in with the current key, until a config listing an available storage releases it.
pub(crate) async fn a_key_storage_required_policy_holds_check_in_renewal(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §check-in
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-metadata
    // oracle: intent crates/agent-identity/INTENT.md §Key storage
    with_agent(ctx, None, false, async move |case| {
        case.set_identity_debug("min_renewal_interval_secs", json!(0))?;
        case.start().await?;
        let target = case.ctx.target.clone();
        target.faults(&json!({ "channel_available": false })).await?;
        set_policy(&target, Some(&holding_policy())).await?;
        let (id, state) = case.enroll_new(&target, 1).await?;
        let authority = field(&state, "authority_id")?.to_owned();
        target.management().request_renewal(&id).await?;
        poll!(case, WAIT, POLL, "no check-in returned renewal_requested", async {
            let requested = target
                .events(&id)
                .await?
                .iter()
                .any(|event| event["type"] == "check_in_received" && event["renewal_requested"] == true);
            Ok(requested.then_some(()))
        });
        assert_no_renewal(
            case,
            &target,
            &authority,
            "its required policy lists no available key storage",
        )
        .await?;
        case.set_metadata_hostname("held-renewal-check-in")?;
        let record = case
            .until_identity(&target, &id, "a check-in during the held renewal", |record| {
                record.metadata_value("hostname") == Some("held-renewal-check-in")
            })
            .await?;
        ensure!(
            count(&target.requests(None).await?, "renew")? == 0,
            "the agent sent a renew request although its required policy lists no available key storage"
        );
        ensure!(
            record.metadata_value("key_storage") == Some(builtin_default()),
            "check-in metadata reports key_storage {:?} for a signing key in {}",
            record.metadata_value("key_storage"),
            builtin_default()
        );
        let releasing = json!({ "backends": [UNLISTED, builtin_default()], "required": true });
        set_policy(&target, Some(&releasing)).await?;
        settled_into(
            case,
            &target,
            &authority,
            &id,
            key_name(&state, "current")?,
            builtin_default(),
        )
        .await?;
        Ok(())
    })
    .await
}

/// While a required policy lists no available key storage, a renewal that the agent's own schedule starts sends no renew request.
pub(crate) async fn a_key_storage_required_policy_holds_scheduled_renewal(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-renewal
    // oracle: intent crates/agent-identity/INTENT.md §Key storage
    // oracle: intent devolutions-agent/src/identity/INTENT.md §Configuration
    with_agent(ctx, Some(1), true, async move |case| {
        let target = case.ctx.target.clone();
        set_policy(&target, Some(&holding_policy())).await?;
        let (id, state) = case.enroll_new(&target, 1).await?;
        let authority = field(&state, "authority_id")?.to_owned();
        case.until_identity(&target, &id, "a working channel", |record| record.connected)
            .await?;
        // The schedule makes the renewal due one second after the certificate's anchor, before the observation starts.
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_no_renewal(
            case,
            &target,
            &authority,
            "its required policy lists no available key storage",
        )
        .await?;
        ensure!(
            case.identity_record(&target, &id).await?.connected,
            "the agent dropped its stream while holding its scheduled renewal back"
        );
        Ok(())
    })
    .await
}

/// A required policy whose listed storages are all unavailable, each beside a malformed variant that differs from it in one member.
///
/// The valid policy holds renewal back; the agent treats its malformed variant as absent, so that variant releases the renewal.
fn policy_pairs() -> Vec<(&'static str, Value, Value)> {
    let names = |count: usize| (0..count).map(|n| format!("zz_{n}")).collect::<Vec<_>>();
    let long = |length: usize| format!("z{}", "a".repeat(length - 1));
    let required = |backends: Value| json!({ "backends": backends, "required": true });
    let base = required(json!(["zz_a"]));
    vec![
        ("empty backends", base.clone(), required(json!([]))),
        ("nine backends", required(json!(names(8))), required(json!(names(9)))),
        (
            "repeated backend",
            required(json!(["zz_a", "zz_b"])),
            required(json!(["zz_a", "zz_a"])),
        ),
        (
            "65-character name",
            required(json!([long(64)])),
            required(json!([long(65)])),
        ),
        ("empty name", base.clone(), required(json!([""]))),
        ("upper-case name", base.clone(), required(json!(["Zz_a"]))),
        ("leading digit", required(json!(["a0"])), required(json!(["0a"]))),
        ("hyphen in name", base.clone(), required(json!(["zz-a"]))),
        ("non-string name", base.clone(), required(json!([1]))),
        ("backends not an array", base.clone(), required(json!("zz_a"))),
        ("backends missing", base.clone(), json!({ "required": true })),
        ("required missing", base.clone(), json!({ "backends": ["zz_a"] })),
        (
            "required a string",
            base.clone(),
            json!({ "backends": ["zz_a"], "required": "true" }),
        ),
        (
            "required a number",
            base.clone(),
            json!({ "backends": ["zz_a"], "required": 1 }),
        ),
        ("policy null", base.clone(), Value::Null),
        ("policy a string", base, json!("zz_a")),
    ]
}

/// A malformed policy is treated as absent: it blocks neither enrollment nor renewal, and the agent still stores its config and revision.
///
/// Each malformed policy follows its valid twin, which holds the requested renewal back, so only the targeted member decides whether the renewal proceeds.
pub(crate) async fn a_key_storage_malformed_policy_is_ignored(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
    // oracle: intent crates/agent-identity/INTENT.md §Key storage
    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
    with_agent(ctx, None, false, async move |case| {
        case.set_identity_debug("min_renewal_interval_secs", json!(0))?;
        case.start().await?;
        let target = case.ctx.target.clone();
        let pairs = policy_pairs();
        let (_, _, enrollment_policy) = pairs.first().context("no malformed policy")?;
        set_policy(&target, Some(enrollment_policy)).await?;
        let (id, state) = case.enroll_new(&target, 1).await?;
        let authority = field(&state, "authority_id")?.to_owned();
        ensure!(
            state["config"].get("key_storage") == Some(enrollment_policy),
            "the agent did not store the enrollment config with its malformed policy as received"
        );
        for (name, valid, malformed) in &pairs {
            set_policy(&target, Some(valid)).await?;
            let held = until_policy_stored(case, &target, &authority, &id, Some(valid)).await?;
            target.management().request_renewal(&id).await?;
            assert_no_renewal(
                case,
                &target,
                &authority,
                "its required policy lists no available key storage",
            )
            .await
            .with_context(|| format!("valid twin of the {name} case"))?;
            set_policy(&target, Some(malformed)).await?;
            let stored = until_policy_stored(case, &target, &authority, &id, Some(malformed))
                .await
                .with_context(|| format!("{name} case"))?;
            ensure!(
                count(&held["config"], "revision")? < count(&stored["config"], "revision")?,
                "the agent did not store the revision of the config with the {name} policy"
            );
            settled_into(
                case,
                &target,
                &authority,
                &id,
                key_name(&held, "current")?,
                builtin_default(),
            )
            .await
            .with_context(|| format!("the {name} policy held the renewal back"))?;
        }
        Ok(())
    })
    .await
}

/// A required policy that excludes the current key's storage while listing an available one makes the agent renew without a schedule or a request: when it stores such a config, and at start-up.
///
/// A required policy that lists the current key's storage starts no renewal.
pub(crate) async fn a_key_storage_required_policy_renews_into_a_listed_storage(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-renewal
    // oracle: intent crates/agent-identity/INTENT.md §Key storage
    // oracle: intent devolutions-agent/src/identity/INTENT.md §Configuration
    with_agent(ctx, None, false, async move |case| {
        case.set_identity_debug("min_renewal_interval_secs", json!(0))?;
        case.start().await?;
        let target = case.ctx.target.clone();
        let to_file = json!({ "backends": [FILE], "required": true });
        set_policy(&target, Some(&to_file)).await?;
        let (id, state) = case.enroll_new(&target, 1).await?;
        let authority = field(&state, "authority_id")?.to_owned();
        let file_state = settled_into(case, &target, &authority, &id, key_name(&state, "current")?, FILE)
            .await
            .context("the enrollment config's policy")?;

        let to_provider = json!({ "backends": [WINDOWS_SOFTWARE_PROVIDER], "required": true });
        set_policy(&target, Some(&to_provider)).await?;
        let provider_state = settled_into(
            case,
            &target,
            &authority,
            &id,
            key_name(&file_state, "current")?,
            WINDOWS_SOFTWARE_PROVIDER,
        )
        .await
        .context("a changed policy")?;

        let listing_current = json!({ "backends": [FILE, WINDOWS_SOFTWARE_PROVIDER], "required": true });
        set_policy(&target, Some(&listing_current)).await?;
        until_policy_stored(case, &target, &authority, &id, Some(&listing_current)).await?;
        assert_no_renewal(case, &target, &authority, "its policy lists the current key's storage").await?;
        ensure!(
            !case.identity_record(&target, &id).await?.renewal_requested,
            "the authority requested a renewal that the case never asked for"
        );

        case.stop().await?;
        // The stored config now asks for the file backend under the revision the authority holds, so only the agent's start-up check can start the renewal.
        let identity = case.identity_path(&authority);
        edit_json_in_place(&identity, |state| state["config"]["key_storage"] = to_file.clone())?;
        case.start().await?;
        settled_into(
            case,
            &target,
            &authority,
            &id,
            key_name(&provider_state, "current")?,
            FILE,
        )
        .await
        .context("a stored policy at start-up")?;
        Ok(())
    })
    .await
}

/// The fresh key that replaces an unusable pending key follows the stored policy, not the built-in default.
///
/// The pending key goes missing from its available storage while the agent is stopped, after the authority issued its certificate.
pub(crate) async fn a_key_storage_policy_applies_to_a_replacement_pending_key(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §agent-renewal
    // oracle: intent crates/agent-identity/INTENT.md §Key storage
    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
    #[cfg(windows)]
    {
        with_agent(ctx, None, false, async move |case| {
            case.set_identity_debug("min_renewal_interval_secs", json!(0))?;
            case.start().await?;
            let target = case.ctx.target.clone();
            let (id, state) = case.enroll_new(&target, 1).await?;
            let authority = field(&state, "authority_id")?.to_owned();
            let current = key_name(&state, "current")?.to_owned();
            case.until_identity(&target, &id, "a working channel", |record| record.connected)
                .await?;
            expect_status(
                &target
                    .control("retry-barrier", &json!({ "endpoint": "confirm", "pause": true }))
                    .await?,
                200,
            )?;
            target
                .faults(&json!({ "fail_next_response": { "endpoint": "confirm", "status": 503 } }))
                .await?;
            target.management().request_renewal(&id).await?;
            let pending = case
                .until_state(
                    &target,
                    &authority,
                    &id,
                    "a pending key with its certificate",
                    |state| state["keys"]["pending"]["certificate_chain"].is_array(),
                )
                .await?;
            ensure!(
                pending["keys"]["pending"]["key_storage"] == WINDOWS_SOFTWARE_PROVIDER,
                "the pending key of a renewal without a policy is not in the built-in default"
            );
            let unusable = key_name(&pending, "pending")?.to_owned();
            case.stop().await?;
            expect_status(
                &target
                    .control("retry-barrier", &json!({ "endpoint": "confirm", "pause": false }))
                    .await?,
                200,
            )?;
            crate::windows::delete_machine_key(&unusable)?;
            let policy = json!({ "backends": [FILE], "required": false });
            set_policy(&target, Some(&policy)).await?;
            // The policy is in the stored config before the agent starts, so the replacement key cannot race the config update.
            edit_json_in_place(&case.identity_path(&authority), |state| {
                state["config"]["key_storage"] = policy.clone();
            })?;
            case.start().await?;
            let settled = settled_into(case, &target, &authority, &id, &current, FILE).await?;
            ensure!(
                key_name(&settled, "current")? != unusable && !key_exists(case, &unusable)?,
                "the agent kept or promoted the unusable pending key"
            );
            Ok(())
        })
        .await
    }
    #[cfg(not(windows))]
    {
        let _ = ctx;
        Err(crate::NotApplicable("needs two available key storages").into())
    }
}

/// An identity whose current key is recorded in a key storage the agent doesn't know is left as it is and unused, without `key_lost`, while the agent's identity with another authority keeps working.
pub(crate) async fn a_current_key_in_unavailable_storage_pauses_only_its_identity(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
    // oracle: intent crates/agent-identity/INTENT.md §Identities
    with_agent(ctx, None, true, async move |case| {
        let first = case.ctx.target.clone();
        let second = case.ctx.second.clone().context("second authority required")?.target;
        let (first_id, first_state) = case.enroll_new(&first, 1).await?;
        let second_token = second
            .management()
            .create_token(1, Duration::from_secs(3600), None)
            .await?;
        case.write_pending(&second_token.text)?;
        let (second_id, _) = case.enrolled(&second, &second_token).await?;
        case.until_identity(&first, &first_id, "a working first channel", |record| record.connected)
            .await?;
        case.until_identity(&second, &second_id, "a working second channel", |record| {
            record.connected
        })
        .await?;
        case.stop().await?;
        let first_path = case.identity_path(field(&first_state, "authority_id")?);
        let paused = edit_json_in_place(&first_path, |state| {
            state["keys"]["current"]["key_storage"] = json!(UNLISTED);
        })?;
        let first_before = signed_requests(&first).await?;
        let second_connects = count(&second.requests(None).await?, "authenticated_connects")?;
        let mark = log_mark(case)?;
        case.start().await?;
        until_authenticated_connect(case, &second, second_connects, "the identity with the second authority").await?;
        until_error_logged(case, mark, "a key in an unknown key storage").await?;
        let started = Instant::now();
        while started.elapsed() < PAUSE_OBSERVATION {
            tokio::time::sleep(POLL).await;
            case.check_running()?;
            ensure!(
                signed_requests(&first).await? == first_before,
                "the agent used an identity whose current key is in an unknown key storage"
            );
            ensure!(
                std::fs::read(&first_path)? == paused,
                "the agent changed the identity file of an identity whose current key is in an unknown key storage"
            );
        }
        Ok(())
    })
    .await
}

/// An identity whose pending key is recorded in a key storage that isn't available is left as it is and unused until the record names an available storage again.
pub(crate) async fn a_pending_key_in_unavailable_storage_pauses_until_restored(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
    // oracle: intent crates/agent-identity/INTENT.md §Identities
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        let (id, state) = case.enroll_new(&target, 1).await?;
        case.until_identity(&target, &id, "a working channel", |record| record.connected)
            .await?;
        case.stop().await?;
        let path = case.identity_path(field(&state, "authority_id")?);
        let original = std::fs::read(&path)?;
        let pending = format!("{}_{}", case.ctx.key_name_prefix, uuid::Uuid::new_v4());
        let paused = edit_json_in_place(&path, |state| {
            state["keys"]["pending"] = json!({ "key_name": pending, "key_storage": key_storage::unavailable() });
        })?;
        let before = signed_requests(&target).await?;
        let mark = log_mark(case)?;
        case.start().await?;
        until_error_logged(case, mark, "a pending key in an unavailable key storage").await?;
        let started = Instant::now();
        while started.elapsed() < PAUSE_OBSERVATION {
            tokio::time::sleep(POLL).await;
            case.check_running()?;
            ensure!(
                signed_requests(&target).await? == before,
                "the agent used an identity whose pending key is in an unavailable key storage"
            );
            ensure!(
                std::fs::read(&path)? == paused,
                "the agent changed the identity file of an identity whose pending key is in an unavailable key storage"
            );
        }
        case.stop().await?;
        rewrite_in_place(&path, &original)?;
        let connects = count(&target.requests(None).await?, "authenticated_connects")?;
        case.start().await?;
        until_authenticated_connect(case, &target, connects, "the restored identity").await?;
        Ok(())
    })
    .await
}

/// A pending file whose in-progress record names a key storage that isn't available waits without enrolling, and enrolls again once the record names an available storage.
pub(crate) async fn a_in_progress_key_in_unavailable_storage_waits(ctx: Context) -> anyhow::Result<()> {
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §key-storage
    // oracle: intent crates/agent-identity/INTENT.md §Identities
    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        let token = new_token(case, 1).await?;
        dropped_enrollment(case, &token).await?;
        case.stop().await?;
        let path = case.in_progress_path();
        let original = std::fs::read(&path)?;
        let waiting = edit_json_in_place(&path, |record| {
            record["key_storage"] = json!(key_storage::unavailable());
        })?;
        let before = enroll_attempts(&target, &token).await?;
        let mark = log_mark(case)?;
        case.start().await?;
        until_error_logged(case, mark, "an enrollment key in an unavailable key storage").await?;
        let started = Instant::now();
        while started.elapsed() < PAUSE_OBSERVATION {
            tokio::time::sleep(POLL).await;
            case.check_running()?;
            ensure!(
                enroll_attempts(&target, &token).await? == before,
                "the agent enrolled with a key recorded in an unavailable key storage"
            );
            ensure!(
                std::fs::read(&path)? == waiting && case.pending_path().exists() && !case.has_stored_identity()?,
                "the agent changed a pending enrollment whose key is in an unavailable key storage"
            );
        }
        case.stop().await?;
        rewrite_in_place(&path, &original)?;
        case.start().await?;
        poll!(
            case,
            WAIT,
            POLL,
            "the restored pending enrollment was not retried",
            async { Ok((enroll_attempts(&target, &token).await? > before).then_some(())) }
        );
        Ok(())
    })
    .await
}

/// Fails if either authority receives a signed request, or the file at `path` changes, while [`PAUSE_OBSERVATION`] elapses.
async fn assert_all_identities_stopped(
    case: &mut AgentCase,
    targets: [&Target; 2],
    path: &Path,
    contents: &[u8],
) -> anyhow::Result<()> {
    let before = [signed_requests(targets[0]).await?, signed_requests(targets[1]).await?];
    let started = Instant::now();
    while started.elapsed() < PAUSE_OBSERVATION {
        tokio::time::sleep(POLL).await;
        case.check_running()?;
        ensure!(
            [signed_requests(targets[0]).await?, signed_requests(targets[1]).await?] == before,
            "the agent kept processing identities with a record it can't use"
        );
        ensure!(
            std::fs::read(path)? == contents,
            "the agent repaired or replaced a record it can't use"
        );
    }
    Ok(())
}

/// An `identity.json` slot without a well-formed `key_storage` stops all identity processing and is left unchanged; the same file with its `key_storage` restored lets both identities work again.
pub(crate) async fn a_identity_file_without_key_storage_stops_identity_processing(ctx: Context) -> anyhow::Result<()> {
    // oracle: intent crates/agent-identity/INTENT.md §Local state
    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
    with_agent(ctx, None, true, async move |case| {
        let first = case.ctx.target.clone();
        let second = case.ctx.second.clone().context("second authority required")?.target;
        let (first_id, first_state) = case.enroll_new(&first, 1).await?;
        let second_token = second
            .management()
            .create_token(1, Duration::from_secs(3600), None)
            .await?;
        case.write_pending(&second_token.text)?;
        let (second_id, _) = case.enrolled(&second, &second_token).await?;
        case.until_identity(&first, &first_id, "a working first channel", |record| record.connected)
            .await?;
        case.until_identity(&second, &second_id, "a working second channel", |record| {
            record.connected
        })
        .await?;
        case.stop().await?;
        let path = case.identity_path(field(&first_state, "authority_id")?);
        let original = std::fs::read(&path)?;
        let storage = field(&first_state["keys"]["current"], "key_storage")?;
        let capitalized = format!("{}{}", storage[..1].to_ascii_uppercase(), &storage[1..]);
        let unusable = [
            ("key_storage removed", None),
            ("key_storage not a name", Some(json!(capitalized))),
        ];
        for (name, replacement) in unusable {
            let contents = edit_json_in_place(&path, |state| {
                let slot = state["keys"]["current"].as_object_mut().expect("stored current slot");
                slot.remove("key_storage");
                if let Some(replacement) = replacement {
                    slot.insert("key_storage".to_owned(), replacement);
                }
            })?;
            case.start().await?;
            assert_all_identities_stopped(case, [&first, &second], &path, &contents)
                .await
                .with_context(|| format!("{name} case"))?;
            case.stop().await?;
            rewrite_in_place(&path, &original)?;
            let connects = [
                count(&first.requests(None).await?, "authenticated_connects")?,
                count(&second.requests(None).await?, "authenticated_connects")?,
            ];
            case.start().await?;
            until_authenticated_connect(case, &first, connects[0], "the first identity, restored").await?;
            until_authenticated_connect(case, &second, connects[1], "the second identity").await?;
            case.stop().await?;
        }
        Ok(())
    })
    .await
}

/// An in-progress record without `key_storage` stops all identity processing and is left unchanged; the same record with its `key_storage` restored lets enrollment and the other identity proceed.
pub(crate) async fn a_in_progress_record_without_key_storage_stops_identity_processing(
    ctx: Context,
) -> anyhow::Result<()> {
    // oracle: intent crates/agent-identity/INTENT.md §Local state
    // oracle: intent crates/agent-identity/INTENT.md §Pending-enrollment files
    with_agent(ctx, None, true, async move |case| {
        let first = case.ctx.target.clone();
        let second = case.ctx.second.clone().context("second authority required")?.target;
        let second_token = second
            .management()
            .create_token(1, Duration::from_secs(3600), None)
            .await?;
        case.write_pending(&second_token.text)?;
        let (second_id, _) = case.enrolled(&second, &second_token).await?;
        case.until_identity(&second, &second_id, "a working second channel", |record| {
            record.connected
        })
        .await?;
        let token = new_token(case, 1).await?;
        dropped_enrollment(case, &token).await?;
        case.stop().await?;
        let path = case.in_progress_path();
        let original = std::fs::read(&path)?;
        let contents = edit_json_in_place(&path, |record| {
            record
                .as_object_mut()
                .expect("in-progress record")
                .remove("key_storage");
        })?;
        let attempts = enroll_attempts(&first, &token).await?;
        case.start().await?;
        assert_all_identities_stopped(case, [&first, &second], &path, &contents).await?;
        ensure!(
            enroll_attempts(&first, &token).await? == attempts && case.pending_path().exists(),
            "the agent processed a pending enrollment whose in-progress record it can't use"
        );
        case.stop().await?;
        rewrite_in_place(&path, &original)?;
        let connects = count(&second.requests(None).await?, "authenticated_connects")?;
        case.start().await?;
        until_authenticated_connect(case, &second, connects, "the second identity").await?;
        poll!(
            case,
            WAIT,
            POLL,
            "the restored pending enrollment was not retried",
            async { Ok((enroll_attempts(&first, &token).await? > attempts).then_some(())) }
        );
        Ok(())
    })
    .await
}

/// Writes a P-256 key file named `name` under `identity/keys`, as a key file that some earlier run left behind.
fn plant_file_key(case: &AgentCase, name: &str) -> anyhow::Result<()> {
    use p256::elliptic_curve::Generate as _;
    use p256::pkcs8::EncodePrivateKey as _;

    let path = case.key_file_path(name);
    let keys = path.parent().context("key directory")?;
    let der = p256::SecretKey::generate_from_rng(&mut rand::rng()).to_pkcs8_der()?;
    #[cfg(windows)]
    {
        crate::windows::create_protected_dirs(keys)?;
        crate::windows::write_protected_file(&path, der.as_bytes())?;
    }
    #[cfg(not(windows))]
    {
        use std::io::Write as _;

        std::fs::create_dir_all(keys)?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        options.open(&path)?.write_all(der.as_bytes())?;
    }
    Ok(())
}

/// At start-up the agent deletes each key with its prefix that no record names with its key storage, in every available storage, and keeps the recorded keys.
///
/// On Windows the planted keys include a key file named like the current key, which its slot records in the Windows software provider.
pub(crate) async fn a_start_deletes_unrecorded_keys_in_every_available_storage(ctx: Context) -> anyhow::Result<()> {
    // oracle: intent crates/agent-identity/INTENT.md §Stored identities
    with_agent(ctx, None, true, async move |case| {
        let target = case.ctx.target.clone();
        let (id, state) = case.enroll_new(&target, 1).await?;
        let current = key_name(&state, "current")?.to_owned();
        case.stop().await?;
        let orphan_file = format!("{}_{}", case.ctx.key_name_prefix, uuid::Uuid::new_v4());
        plant_file_key(case, &orphan_file)?;
        #[cfg(windows)]
        let orphan_machine_key = {
            let name = format!("{}_{}", case.ctx.key_name_prefix, uuid::Uuid::new_v4());
            crate::windows::create_machine_key(&name)?;
            plant_file_key(case, &current)?;
            name
        };
        ensure!(
            case.data_dir().audit_orphan_keys().is_err(),
            "the planted keys are not unrecorded keys"
        );
        case.start().await?;
        let orphan_path = case.key_file_path(&orphan_file);
        #[cfg(windows)]
        let shadow_path = case.key_file_path(&current);
        poll!(
            case,
            WAIT,
            POLL,
            "the agent kept unrecorded keys after start-up",
            async {
                #[cfg(windows)]
                let deleted = !orphan_path.exists()
                    && !shadow_path.exists()
                    && !crate::windows::machine_key_exists(&orphan_machine_key)?;
                #[cfg(not(windows))]
                let deleted = !orphan_path.exists();
                Ok(deleted.then_some(()))
            }
        );
        ensure!(
            slot_key_exists(case, &state, "current")?,
            "start-up deleted the recorded current key"
        );
        case.set_metadata_hostname("after-orphan-cleanup")?;
        case.until_identity(&target, &id, "the identity signing after start-up", |record| {
            record.metadata_value("hostname") == Some("after-orphan-cleanup")
        })
        .await?;
        Ok(())
    })
    .await
}
