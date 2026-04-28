use super::*;

fn token_with_jti(jti: Uuid) -> String {
    let header = base64_url_no_pad(br#"{"alg":"RS256","typ":"JWT"}"#);
    let payload = base64_url_no_pad(format!(r#"{{"jti":"{jti}"}}"#).as_bytes());
    format!("{header}.{payload}.ZHVtbXlfc2lnbmF0dXJl")
}

fn base64_url_no_pad(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);

    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);

        output.push(ALPHABET[(b0 >> 2) as usize] as char);
        output.push(ALPHABET[(((b0 & 0b0000_0011) << 4) | (b1 >> 4)) as usize] as char);

        if chunk.len() > 1 {
            output.push(ALPHABET[(((b1 & 0b0000_1111) << 2) | (b2 >> 6)) as usize] as char);
        }

        if chunk.len() > 2 {
            output.push(ALPHABET[(b2 & 0b0011_1111) as usize] as char);
        }
    }

    output
}

fn cleartext_mapping(proxy_username: &str) -> CleartextAppCredentialMapping {
    CleartextAppCredentialMapping {
        proxy: CleartextAppCredential::UsernamePassword {
            username: proxy_username.to_owned(),
            password: secrecy::SecretString::from("proxy-password"),
        },
        target: CleartextAppCredential::UsernamePassword {
            username: "target@example.invalid".to_owned(),
            password: secrecy::SecretString::from("target-password"),
        },
    }
}

#[test]
fn insert_generates_id_and_indexes_by_token() {
    let store = CredentialStoreHandle::new();
    let token = token_with_jti(Uuid::new_v4());

    let (cred_injection_id, entry) = store
        .insert(
            token.clone(),
            Some(cleartext_mapping("proxy@example.invalid")),
            None,
            time::Duration::minutes(5),
        )
        .expect("insert succeeds");

    assert!(entry.is_none());
    assert_eq!(
        store
            .get(cred_injection_id)
            .expect("entry is indexed by generated id")
            .cred_injection_id,
        cred_injection_id
    );
    assert_eq!(
        store
            .get_by_token(&token)
            .expect("entry is indexed by association token")
            .cred_injection_id,
        cred_injection_id
    );
}

#[test]
fn insert_preserves_supplied_id() {
    let store = CredentialStoreHandle::new();
    let supplied_id = Uuid::new_v4();

    let (cred_injection_id, _) = store
        .insert(
            token_with_jti(Uuid::new_v4()),
            Some(cleartext_mapping("proxy@example.invalid")),
            Some(supplied_id),
            time::Duration::minutes(5),
        )
        .expect("insert succeeds");

    assert_eq!(cred_injection_id, supplied_id);
}

#[test]
fn insert_evicts_previous_entry_on_jti_collision() {
    let store = CredentialStoreHandle::new();
    let jti = Uuid::new_v4();
    let token = token_with_jti(jti);
    let first_id = Uuid::new_v4();
    let second_id = Uuid::new_v4();

    store
        .insert(
            token.clone(),
            Some(cleartext_mapping("proxy@example.invalid")),
            Some(first_id),
            time::Duration::minutes(5),
        )
        .expect("first insert succeeds");
    let (_, previous) = store
        .insert(
            token.clone(),
            Some(cleartext_mapping("proxy@example.invalid")),
            Some(second_id),
            time::Duration::minutes(5),
        )
        .expect("second insert succeeds");

    assert_eq!(
        previous.expect("previous entry is returned").cred_injection_id,
        first_id
    );
    assert!(store.get(first_id).is_none());
    assert_eq!(
        store
            .get_by_token(&token)
            .expect("token points to replacement entry")
            .cred_injection_id,
        second_id
    );
}

#[test]
fn entries_with_same_proxy_username_can_coexist() {
    let store = CredentialStoreHandle::new();
    let first_token = token_with_jti(Uuid::new_v4());
    let second_token = token_with_jti(Uuid::new_v4());
    let proxy_username = Uuid::new_v4().to_string();

    let (first_id, _) = store
        .insert(
            first_token.clone(),
            Some(cleartext_mapping(&proxy_username)),
            None,
            time::Duration::minutes(5),
        )
        .expect("first insert succeeds");
    let (second_id, _) = store
        .insert(
            second_token.clone(),
            Some(cleartext_mapping(&proxy_username)),
            None,
            time::Duration::minutes(5),
        )
        .expect("second insert succeeds");

    assert_ne!(first_id, second_id);
    assert_eq!(
        store
            .get_by_token(&first_token)
            .expect("first token remains indexed")
            .cred_injection_id,
        first_id
    );
    assert_eq!(
        store
            .get_by_token(&second_token)
            .expect("second token remains indexed")
            .cred_injection_id,
        second_id
    );
}

#[test]
fn uuid_proxy_username_gets_synthetic_realm() {
    let store = CredentialStoreHandle::new();
    let proxy_username = Uuid::new_v4().to_string();

    let (cred_injection_id, _) = store
        .insert(
            token_with_jti(Uuid::new_v4()),
            Some(cleartext_mapping(&proxy_username)),
            None,
            time::Duration::minutes(5),
        )
        .expect("insert succeeds");

    let entry = store.get(cred_injection_id).expect("entry exists");
    let kerberos = entry.kerberos.as_ref().expect("Kerberos state exists");
    assert_eq!(kerberos.realm, synthetic_realm(cred_injection_id));
    assert!(!kerberos.realm.is_empty());
}
