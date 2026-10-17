use nddev_device_sync_accounts::{IdentityClient, SessionStore};
use serde_json::Value;
use std::{path::PathBuf, time::Duration};

#[tokio::test]
#[ignore = "requires an explicitly started isolated PostgreSQL/Mailpit fixture"]
async fn actual_mailbox_session_persistence_and_revocation() {
    let receipt = PathBuf::from(
        std::env::var("NDS_FIXTURE_RECEIPT").expect("explicit fixture receipt required"),
    );
    let data: Value = serde_json::from_slice(&std::fs::read(receipt).unwrap()).unwrap();
    let endpoint = data["base_url"].as_str().unwrap();
    let mailbox = data["mailpit_url"].as_str().unwrap();
    let owner = data["owner_email"].as_str().unwrap();
    assert!(endpoint.starts_with("http://127.0.0.1:"));
    assert!(mailbox.starts_with("http://127.0.0.1:"));
    let client = IdentityClient::new(endpoint).unwrap();
    let view = client.refresh().await.unwrap();
    assert!(view.email_available);
    assert!(!view.authenticated);
    let http = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let prior: Value = http
        .get(format!("{mailbox}/api/v1/messages"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let prior_ids: Vec<String> = prior["messages"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|message| message["ID"].as_str().map(str::to_owned))
        .collect();
    let challenge = client.request_email(owner.to_owned(), "ru").await.unwrap();
    assert_eq!(challenge.flow, "email");
    let code = tokio::time::timeout(Duration::from_secs(10), async {
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
                .and_then(|items| {
                    items.iter().find(|message| {
                        message["ID"]
                            .as_str()
                            .is_some_and(|id| !prior_ids.iter().any(|old| old == id))
                    })
                })
                .and_then(|message| message["ID"].as_str())
            {
                let message: Value = http
                    .get(format!("{mailbox}/api/v1/message/{id}"))
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                let text = message["Text"].as_str().unwrap();
                if let Some((_, suffix)) = text
                    .split_once("код входа: ")
                    .or_else(|| text.split_once("code: "))
                {
                    let code: String = suffix.chars().take(8).collect();
                    if code.len() == 8 && code.bytes().all(|b| b.is_ascii_digit()) {
                        break code;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    let view = client.verify_email(code).await.unwrap();
    assert!(view.authenticated);
    assert_eq!(view.auth_method, "email_otp");
    if data["client_policy"].as_bool() == Some(true) {
        use nddev_device_sync_accounts::SyncRequest;
        let enrolled = client
            .enroll_device("Owned policy acceptance".into())
            .await
            .unwrap();
        assert!(!enrolled.current_device_id.is_empty());
        let policy = client
            .sync_request(SyncRequest::TelemetryPolicy)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&policy.body).unwrap(),
            serde_json::json!({"export_mode":"enabled"})
        );
        if data["operator"].as_bool() == Some(false) {
            let error = client
                .sync_request(SyncRequest::ObservabilityStatus)
                .await
                .err()
                .expect("operator request must be denied");
            assert_eq!(error.code(), "authorization_denied");
            assert!(client.view().authenticated);
            assert!(
                client
                    .sync_request(SyncRequest::TelemetryPolicy)
                    .await
                    .is_ok()
            );
        }
    }
    let another = IdentityClient::new(endpoint).unwrap();
    let restored = another.refresh().await.unwrap();
    assert!(restored.authenticated);
    assert!(restored.user_id == view.user_id && restored.tenant_id == view.tenant_id);
    let store =
        SessionStore::for_endpoint(&format!("{}/", endpoint.trim_end_matches('/'))).unwrap();
    let old = store.read().await.unwrap().unwrap();
    assert!(!another.logout().await.unwrap().authenticated);
    assert!(store.read().await.unwrap().is_none());
    let status = http
        .get(format!("{endpoint}/v2/session"))
        .bearer_auth(std::str::from_utf8(&old).unwrap())
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
    assert!(
        !IdentityClient::new(endpoint)
            .unwrap()
            .refresh()
            .await
            .unwrap()
            .authenticated
    );
}
