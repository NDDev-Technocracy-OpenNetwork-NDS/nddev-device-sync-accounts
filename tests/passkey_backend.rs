//! Browser-driven acceptance against an owned PostgreSQL/Mailpit fixture.
use nddev_device_sync_accounts::{IdentityClient, SessionStore};
use serde_json::Value;
use std::{path::PathBuf, time::Duration};

#[tokio::test]
#[ignore = "requires an owned localhost fixture and an actual browser authenticator"]
async fn browser_passkey_registration_login_restore_and_revocation() {
    let receipt: Value = serde_json::from_slice(
        &std::fs::read(std::env::var("NDS_FIXTURE_RECEIPT").unwrap()).unwrap(),
    )
    .unwrap();
    let endpoint = receipt["base_url"].as_str().unwrap();
    let mailbox = receipt["mailpit_url"].as_str().unwrap();
    assert!(endpoint.starts_with("http://localhost:"));
    let handoff = PathBuf::from(std::env::var("NDS_PASSKEY_HANDOFF_FILE").unwrap());
    assert!(
        handoff.is_absolute()
            && !handoff.starts_with(env!("CARGO_MANIFEST_DIR"))
            && !handoff.exists()
    );
    let client = IdentityClient::new(endpoint).unwrap();
    assert!(!client.refresh().await.unwrap().authenticated);
    let http = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let before: Value = http
        .get(format!("{mailbox}/api/v1/messages"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let before: Vec<String> = before["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|message| message["ID"].as_str().map(str::to_owned))
        .collect();
    client
        .request_email(receipt["owner_email"].as_str().unwrap().into(), "en")
        .await
        .unwrap();
    let otp = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let messages: Value = http
                .get(format!("{mailbox}/api/v1/messages"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            if let Some(id) = messages["messages"]
                .as_array()
                .unwrap()
                .first()
                .and_then(|message| message["ID"].as_str())
                .filter(|id| !before.iter().any(|previous| previous == id))
            {
                let message: Value = http
                    .get(format!("{mailbox}/api/v1/message/{id}"))
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                if let Some((_, suffix)) = message["Text"].as_str().unwrap().split_once("code: ") {
                    break suffix.chars().take(8).collect::<String>();
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    let initial = client.verify_email(otp).await.unwrap();
    let owner = (initial.user_id, initial.tenant_id);
    let native = SessionStore::for_endpoint(&format!("{endpoint}/")).unwrap();
    let otp_session = native.read().await.unwrap().unwrap();
    if receipt["multiple_active_accounts"].as_bool() == Some(true) {
        assert_eq!(
            client
                .start_passkey(false, None, "en")
                .await
                .unwrap_err()
                .code(),
            "authentication_failed"
        );
        assert!(client.view().authenticated);
    }
    let mut first_key = String::new();
    let mut first_session = None;
    for (phase, registration) in [true, false, true, false].into_iter().enumerate() {
        let view = client
            .start_passkey(
                registration,
                (!registration).then(|| receipt["owner_email"].as_str().unwrap().into()),
                "en",
            )
            .await
            .unwrap();
        let mut file = std::fs::OpenOptions::new();
        file.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            file.mode(0o600);
        }
        let mut file = file.open(&handoff).unwrap();
        use std::io::Write;
        file.write_all(serde_json::to_string(&serde_json::json!({"authorization_url":view.authorization_url,"verification_code":view.verification_code,"registration":registration,"phase":phase})).unwrap().as_bytes()).unwrap();
        tokio::time::timeout(Duration::from_secs(300), async {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let view = client.poll_passkey().await.unwrap();
                if view.flow.is_empty() {
                    assert!(view.authenticated && view.session_verified);
                    assert_eq!((&view.user_id, &view.tenant_id), (&owner.0, &owner.1));
                    if !registration {
                        assert_eq!(view.auth_method, "passkey");
                    }
                    break;
                }
            }
        })
        .await
        .unwrap();
        std::fs::remove_file(&handoff).unwrap();
        if phase == 0 {
            first_key = client.passkeys().await.unwrap()[0].id.clone();
            if let Some(other) = receipt["other_email"].as_str() {
                assert_eq!(
                    client
                        .start_passkey(false, Some(other.into()), "en")
                        .await
                        .unwrap_err()
                        .code(),
                    "authentication_failed"
                );
                assert_eq!(client.view().user_id, owner.0);
                assert!(client.view().authenticated);
            }
        }
        if phase == 1 {
            first_session = Some(native.read().await.unwrap().unwrap());
        }
    }
    client
        .prepare_device("Owned browser acceptance".into())
        .await
        .unwrap();
    let restored = IdentityClient::new(endpoint).unwrap();
    let view = restored.refresh().await.unwrap();
    assert!(view.authenticated && view.session_verified);
    assert_eq!(view.auth_method, "passkey");
    restored.refresh_devices().await.unwrap();
    restored.authorize_local().await.unwrap();
    let native = SessionStore::for_endpoint(&format!("{endpoint}/")).unwrap();
    let token = native.read().await.unwrap().unwrap();
    let keys = restored.passkeys().await.unwrap();
    assert_eq!(keys.len(), 2);
    let first_session = first_session.unwrap();
    assert_eq!(
        http.get(format!("{endpoint}/v2/session"))
            .bearer_auth(std::str::from_utf8(&first_session).unwrap())
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::OK
    );
    let still_active = restored.revoke_passkey(first_key.clone()).await.unwrap();
    assert!(
        still_active.authenticated
            && still_active.session_verified
            && still_active.passkey_available
    );
    restored.authorize_local().await.unwrap();
    assert_eq!(
        http.get(format!("{endpoint}/v2/session"))
            .bearer_auth(std::str::from_utf8(&first_session).unwrap())
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    let remaining = restored.passkeys().await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert_ne!(remaining[0].id, first_key);
    // Missing fingerprints are idempotently absent under the still-valid login.
    assert!(
        restored
            .revoke_passkey(first_key)
            .await
            .unwrap()
            .authenticated
    );
    let revoked = restored
        .revoke_passkey(remaining[0].id.clone())
        .await
        .unwrap();
    assert!(!revoked.authenticated && !revoked.session_verified && !revoked.passkey_available);
    assert!(client.authorize_local().await.is_err());
    // Committed revocation invalidates the server session atomically. Ordinary
    // refresh then removes its stale cached bearer without touching device keys.
    let refreshed = restored.refresh().await.unwrap();
    assert!(!refreshed.authenticated && !refreshed.passkey_available);
    assert!(native.read().await.unwrap().is_none());
    assert!(
        restored
            .start_passkey(
                false,
                Some(receipt["owner_email"].as_str().unwrap().into()),
                "en"
            )
            .await
            .is_err()
    );
    assert_eq!(
        http.get(format!("{endpoint}/v2/session"))
            .bearer_auth(std::str::from_utf8(&token).unwrap())
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    // Removing both passkeys must not revoke a session established by OTP.
    assert_eq!(
        http.get(format!("{endpoint}/v2/session"))
            .bearer_auth(std::str::from_utf8(&otp_session).unwrap())
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::OK
    );
    assert_eq!(
        http.delete(format!("{endpoint}/v2/session"))
            .bearer_auth(std::str::from_utf8(&otp_session).unwrap())
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::NO_CONTENT
    );
}
