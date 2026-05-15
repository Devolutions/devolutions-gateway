use super::*;

fn cleartext_mapping(proxy_username: &str) -> CleartextAppCredentialMapping {
    CleartextAppCredentialMapping {
        proxy: CleartextAppCredential::UsernamePassword {
            username: proxy_username.to_owned(),
            password: SecretString::from("proxy-password"),
        },
        target: CleartextAppCredential::UsernamePassword {
            username: "target@example.invalid".to_owned(),
            password: SecretString::from("target-password"),
        },
    }
}

#[test]
fn insert_indexes_by_jti() {
    let store = CredentialStoreHandle::new();
    let jti = Uuid::new_v4();

    let previous = store
        .insert(
            jti,
            "raw-token".to_owned(),
            Some((cleartext_mapping("proxy@example.invalid"), "target.example".to_owned())),
            time::Duration::minutes(5),
        )
        .expect("insert succeeds");

    assert!(previous.is_none());
    let entry = store.get(jti).expect("entry is indexed by JTI");
    assert_eq!(entry.jti, jti);
    assert_eq!(entry.token, "raw-token");
    assert_eq!(
        entry
            .injection
            .as_ref()
            .expect("injection state present")
            .target_hostname,
        "target.example"
    );
}

#[test]
fn re_insert_under_same_jti_replaces_entry() {
    let store = CredentialStoreHandle::new();
    let jti = Uuid::new_v4();

    store
        .insert(
            jti,
            "token-a".to_owned(),
            Some((cleartext_mapping("proxy@example.invalid"), "host-a".to_owned())),
            time::Duration::minutes(5),
        )
        .expect("first insert succeeds");
    let previous = store
        .insert(
            jti,
            "token-b".to_owned(),
            Some((cleartext_mapping("proxy@example.invalid"), "host-b".to_owned())),
            time::Duration::minutes(5),
        )
        .expect("second insert succeeds");

    let previous = previous.expect("replacement must report previous entry");
    assert_eq!(previous.jti, jti);
    assert_eq!(previous.token, "token-a");

    let current = store.get(jti).expect("replacement entry present");
    assert_eq!(current.token, "token-b");
}

#[test]
fn distinct_jtis_coexist() {
    let store = CredentialStoreHandle::new();
    let first_jti = Uuid::new_v4();
    let second_jti = Uuid::new_v4();

    store
        .insert(
            first_jti,
            "token-1".to_owned(),
            Some((cleartext_mapping("proxy@example.invalid"), "h1".to_owned())),
            time::Duration::minutes(5),
        )
        .expect("first insert succeeds");
    store
        .insert(
            second_jti,
            "token-2".to_owned(),
            Some((cleartext_mapping("proxy@example.invalid"), "h2".to_owned())),
            time::Duration::minutes(5),
        )
        .expect("second insert succeeds");

    assert_eq!(store.get(first_jti).expect("first entry").jti, first_jti);
    assert_eq!(store.get(second_jti).expect("second entry").jti, second_jti);
}

#[test]
fn lookup_filters_expired_entries() {
    let store = CredentialStoreHandle::new();
    let jti = Uuid::new_v4();

    store
        .insert(
            jti,
            "raw-token".to_owned(),
            Some((cleartext_mapping("proxy@example.invalid"), "host".to_owned())),
            // Negative TTL: entry is born already expired. Validates the lookup-time filter
            // without depending on real elapsed time in tests.
            time::Duration::seconds(-1),
        )
        .expect("insert succeeds");

    assert!(store.get(jti).is_none(), "expired entry must not be returned");
}

#[test]
fn provision_token_entry_has_no_injection_state() {
    let store = CredentialStoreHandle::new();
    let jti = Uuid::new_v4();

    store
        .insert(jti, "raw-token".to_owned(), None, time::Duration::minutes(5))
        .expect("insert succeeds");

    let entry = store.get(jti).expect("entry exists");
    assert!(entry.injection.is_none());
}
