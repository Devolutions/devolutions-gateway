#![allow(unused_crate_dependencies)]
#![allow(clippy::unwrap_used)]

use provisioner_task_store_libsql::{LibSqlProvisionerTaskStore, NewTask, TaskState};
use uuid::Uuid;

fn new_task<'a>(id: Uuid, token_jti: Uuid) -> NewTask<'a> {
    NewTask {
        id,
        kind: "ai-log",
        target: r#"{"sessionId":"3e2b1d6c-5d1a-4a8c-9a8c-1d6f9b2a4c11"}"#,
        params: r#"{"provider":"openai","model":"gpt-test"}"#,
        token_jti,
    }
}

async fn memory_store() -> LibSqlProvisionerTaskStore {
    LibSqlProvisionerTaskStore::open(":memory:").await.unwrap()
}

#[tokio::test]
async fn migrations_set_user_version_and_are_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("provisioner_tasks.db");
    let path = path.to_str().unwrap();

    let id = Uuid::new_v4();
    {
        let store = LibSqlProvisionerTaskStore::open(path).await.unwrap();
        store.insert(new_task(id, Uuid::new_v4())).await.unwrap();
    }

    let store = LibSqlProvisionerTaskStore::open(path).await.unwrap();
    assert!(store.get(id).await.unwrap().is_some());

    let conn = libsql::Builder::new_local(path)
        .build()
        .await
        .unwrap()
        .connect()
        .unwrap();
    let row = conn
        .query("PRAGMA user_version", ())
        .await
        .unwrap()
        .next()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.get::<u64>(0).unwrap(), 1);
}

#[tokio::test]
async fn insert_then_read_back() {
    let store = memory_store().await;
    let id = Uuid::new_v4();
    let jti = Uuid::new_v4();

    store.insert(new_task(id, jti)).await.unwrap();

    let record = store.get(id).await.unwrap().unwrap();
    assert_eq!(record.id, id);
    assert_eq!(record.kind, "ai-log");
    assert_eq!(record.target, r#"{"sessionId":"3e2b1d6c-5d1a-4a8c-9a8c-1d6f9b2a4c11"}"#);
    assert_eq!(record.params, r#"{"provider":"openai","model":"gpt-test"}"#);
    assert_eq!(record.state, TaskState::NotStarted);
    assert_eq!(record.attempts, 0);
    assert_eq!(record.token_jti, jti);
    assert!(record.substate.is_none() && record.result.is_none() && record.error.is_none());
    assert!(record.started_at.is_none() && record.finished_at.is_none());
    assert!(record.created_at > 0);

    assert!(store.get(Uuid::new_v4()).await.unwrap().is_none());
}

#[tokio::test]
async fn attempts_substate_retry_and_success() {
    let store = memory_store().await;
    let id = Uuid::new_v4();
    store.insert(new_task(id, Uuid::new_v4())).await.unwrap();

    assert_eq!(
        store.start_attempt(id, r#"{"step":"preparing"}"#).await.unwrap(),
        Some(1)
    );
    let record = store.get(id).await.unwrap().unwrap();
    assert_eq!(record.state, TaskState::Running);
    assert_eq!(record.substate.as_deref(), Some(r#"{"step":"preparing"}"#));
    assert!(record.started_at.is_some());

    store.set_substate(id, r#"{"step":"reading"}"#).await.unwrap();
    assert_eq!(
        store.get(id).await.unwrap().unwrap().substate.as_deref(),
        Some(r#"{"step":"reading"}"#)
    );

    store.retry_later(id, "rate limited").await.unwrap();
    let record = store.get(id).await.unwrap().unwrap();
    assert_eq!(record.state, TaskState::NotStarted);
    assert_eq!(record.error.as_deref(), Some("rate limited"));
    assert!(record.substate.is_none());

    assert_eq!(store.start_attempt(id, "null").await.unwrap(), Some(2));
    assert!(store.succeed(id, r#"{"log":"log-1.slog"}"#).await.unwrap());

    let record = store.get(id).await.unwrap().unwrap();
    assert_eq!(record.state, TaskState::Success);
    assert_eq!(record.result.as_deref(), Some(r#"{"log":"log-1.slog"}"#));
    assert!(record.error.is_none());
    assert!(record.finished_at.is_some());
    assert_eq!(record.attempts, 2);
}

#[tokio::test]
async fn finished_tasks_are_not_changed_again() {
    let store = memory_store().await;
    let id = Uuid::new_v4();
    store.insert(new_task(id, Uuid::new_v4())).await.unwrap();

    assert!(store.fail(id, "boom").await.unwrap());
    assert!(!store.fail(id, "again").await.unwrap());
    assert!(!store.succeed(id, "1").await.unwrap());
    assert_eq!(store.start_attempt(id, "null").await.unwrap(), None);
    store.set_substate(id, "2").await.unwrap();

    let record = store.get(id).await.unwrap().unwrap();
    assert_eq!(record.state, TaskState::Failed);
    assert_eq!(record.error.as_deref(), Some("boom"));
    assert!(record.substate.is_none() && record.result.is_none());
}

#[tokio::test]
async fn unfinished_lists_not_started_and_running_tasks() {
    let store = memory_store().await;
    let [not_started, running, succeeded, failed] = [(); 4].map(|()| Uuid::new_v4());

    for id in [not_started, running, succeeded, failed] {
        store.insert(new_task(id, Uuid::new_v4())).await.unwrap();
    }

    store.start_attempt(running, "null").await.unwrap();
    store.succeed(succeeded, "null").await.unwrap();
    store.fail(failed, "boom").await.unwrap();

    let mut unfinished = store.unfinished().await.unwrap();
    unfinished.sort();
    let mut expected = vec![not_started, running];
    expected.sort();

    assert_eq!(unfinished, expected);
}

#[tokio::test]
async fn rows_are_never_deleted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("provisioner_tasks.db");
    let path = path.to_str().unwrap();

    let ids = [(); 3].map(|()| Uuid::new_v4());
    {
        let store = LibSqlProvisionerTaskStore::open(path).await.unwrap();
        for id in ids {
            store.insert(new_task(id, Uuid::new_v4())).await.unwrap();
        }
        store.succeed(ids[0], "null").await.unwrap();
        store.fail(ids[1], "boom").await.unwrap();
    }

    let store = LibSqlProvisionerTaskStore::open(path).await.unwrap();
    for id in ids {
        assert!(store.get(id).await.unwrap().is_some(), "{id}");
    }
}

#[tokio::test]
async fn duplicate_id_is_rejected() {
    let store = memory_store().await;
    let id = Uuid::new_v4();

    store.insert(new_task(id, Uuid::new_v4())).await.unwrap();
    assert!(store.insert(new_task(id, Uuid::new_v4())).await.is_err());
}
