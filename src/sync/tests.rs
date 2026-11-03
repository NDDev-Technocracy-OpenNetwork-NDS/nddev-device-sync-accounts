use super::*;
use nddev_device_sync_domain::sync::{MAX_OPERATION_BYTES, MAX_REVISION};

#[test]
fn original_append_bytes_survive_dispatch_and_fresh_nonce_retry() {
    let original = b"{ \"schema_version\":3,\"operation_id\":\"v3:7:owned\" }\n".to_vec();
    let pointer = original.as_ptr();
    let (method, path, body) = SyncRequest::AppendV3(original.clone()).prepare().unwrap();
    let first = body.unwrap();
    let (_, _, moved) = SyncRequest::AppendV3(original).prepare().unwrap();
    let retry = moved.unwrap();
    assert_eq!(retry.as_ptr(), pointer);
    assert_eq!(first, retry);
    assert_eq!(method, Method::POST);
    assert_eq!(path, "/v3/sync/operations");
    let key = Key {
        key: ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
        id: "d".repeat(43),
    };
    let target = format!("https://example.invalid{path}");
    let now = 1_800_000_000;
    let first_signature =
        signatures::sign("POST", &target, &first, &key, &"a".repeat(32), now).unwrap();
    let retry_signature =
        signatures::sign("POST", &target, &retry, &key, &"b".repeat(32), now).unwrap();
    assert_eq!(
        first_signature.content_digest,
        retry_signature.content_digest
    );
    assert_ne!(first_signature.signature, retry_signature.signature);
    assert!(signatures::verify("POST", &target, &retry, &retry_signature, &key, now).is_ok());
    assert!(signatures::verify("POST", &target, b"{}", &retry_signature, &key, now).is_err());
    assert!(
        signatures::verify(
            "POST",
            "https://other.invalid/v3/sync/operations",
            &retry,
            &retry_signature,
            &key,
            now
        )
        .is_err()
    );
}

impl signatures::VerifyingKey for Key {
    fn verify(&self, data: &[u8], signature: &[u8]) -> signatures::HttpSigResult<()> {
        let signature = ed25519_dalek::Signature::from_slice(signature)
            .map_err(|_| signatures::HttpSigError::InvalidSignature("invalid".into()))?;
        self.key
            .verifying_key()
            .verify_strict(data, &signature)
            .map_err(|_| signatures::HttpSigError::InvalidSignature("invalid".into()))
    }
    fn key_id(&self) -> String {
        self.id.clone()
    }
    fn alg(&self) -> signatures::AlgorithmName {
        signatures::AlgorithmName::Ed25519
    }
}

#[test]
fn fixed_routes_enforce_query_and_original_byte_bounds() {
    for request in [
        SyncRequest::AppendV3(Vec::new()),
        SyncRequest::AppendV3(vec![0; MAX_OPERATION_BYTES + 1]),
        SyncRequest::HistoryV3 {
            after: MAX_REVISION + 1,
            limit: 1,
        },
        SyncRequest::HistoryV3 { after: 0, limit: 0 },
        SyncRequest::HistoryV3 {
            after: 0,
            limit: 101,
        },
        SyncRequest::BaseV3 {
            base: MAX_REVISION + 1,
            after_member: 0,
            limit: 1,
        },
        SyncRequest::BaseV3 {
            base: 0,
            after_member: MAX_REVISION + 1,
            limit: 1,
        },
        SyncRequest::BaseV3 {
            base: 0,
            after_member: 0,
            limit: 0,
        },
    ] {
        assert!(matches!(request.prepare(), Err(ClientError::InvalidInput)));
    }
    assert!(
        SyncRequest::AppendV3(vec![0; MAX_OPERATION_BYTES])
            .prepare()
            .is_ok()
    );
    let (method, path, body) = SyncRequest::CapabilitiesV3.prepare().unwrap();
    assert_eq!((method, path, body), (Method::GET, "/v3/sync".into(), None));
    let (_, path, body) = SyncRequest::HistoryV3 {
        after: MAX_REVISION,
        limit: 100,
    }
    .prepare()
    .unwrap();
    assert_eq!(
        path,
        format!("/v3/sync/history?after_seq={MAX_REVISION}&limit=100")
    );
    assert!(body.is_none());
    let (_, path, _) = SyncRequest::BaseV3 {
        base: 42,
        after_member: 7,
        limit: 1,
    }
    .prepare()
    .unwrap();
    assert_eq!(path, "/v3/sync/base?base_seq=42&after_member_seq=7&limit=1");
}

#[test]
fn expired_is_typed_unknown_and_retains_exact_response_bytes() {
    for reason in [
        "basis_expired",
        "cursor_expired",
        "checkpoint_expired",
        "legacy_outcome_unknown",
    ] {
        let original = format!(
            "{{ \"schema_version\":3,\"error\":\"{reason}\",\"floor_seq\":7,\"head_seq\":9 }}\n"
        )
        .into_bytes();
        let reply = SyncReply {
            status: 410,
            body: original.clone(),
        };
        let Some(SyncExpiry::V3(expired)) = reply.expiry().unwrap() else {
            panic!("expected typed V3 expiry");
        };
        assert_eq!((expired.floor_seq, expired.head_seq), (7, 9));
        assert_eq!(reply.body, original);
    }
    let original = b"{ \"error\":\"cursor_expired\" }\n".to_vec();
    let reply = SyncReply {
        status: 410,
        body: original.clone(),
    };
    assert!(matches!(
        reply.expiry().unwrap(),
        Some(SyncExpiry::V2CursorExpired)
    ));
    assert_eq!(reply.body, original);
    for status in [201, 409, 503] {
        assert!(
            SyncReply {
                status,
                body: b"not an expiry".to_vec()
            }
            .expiry()
            .unwrap()
            .is_none()
        );
    }
}

#[test]
fn expiry_rejects_unsupported_shape_and_impossible_history() {
    for body in [
        r#"{"schema_version":2,"error":"basis_expired","floor_seq":0,"head_seq":1}"#,
        r#"{"schema_version":3,"error":"basis_expired","floor_seq":2,"head_seq":1}"#,
        r#"{"schema_version":3,"error":"basis_expired","floor_seq":-1,"head_seq":1}"#,
        r#"{"schema_version":3,"error":"basis_expired","floor_seq":0,"head_seq":9007199254740992}"#,
        r#"{"schema_version":3,"error":"basis_expired","floor_seq":0,"head_seq":1,"unexpected":true}"#,
        r#"{"schema_version":3,"error":"future_error","floor_seq":0,"head_seq":1}"#,
        r#"{"error":"authentication_failed"}"#,
        r#"{"error":"cursor_expired","head_seq":1}"#,
    ] {
        let reply = SyncReply {
            status: 410,
            body: body.as_bytes().to_vec(),
        };
        assert!(matches!(reply.expiry(), Err(ClientError::InvalidResponse)));
    }
    assert!(matches!(
        decode_expired_v3(&vec![b' '; crate::MAX_BODY + 1]),
        Err(ClientError::InvalidResponse)
    ));
    assert!(decode_expired_v3(br#"{"error":"cursor_expired"}"#).is_err());
    assert!(
        decode_expired_v2(
            br#"{"schema_version":3,"error":"cursor_expired","floor_seq":0,"head_seq":1}"#
        )
        .is_err()
    );
}

#[test]
fn legacy_v2_and_observability_routes_keep_their_exact_targets_and_bodies() {
    for (request, expected) in [
        (
            SyncRequest::Append(vec![1, 2, 3]),
            (
                Method::POST,
                "/v2/sync/operations".into(),
                Some(vec![1, 2, 3]),
            ),
        ),
        (
            SyncRequest::Page { after: 7, limit: 3 },
            (
                Method::GET,
                "/v2/sync/operations?after_seq=7&limit=3".into(),
                None,
            ),
        ),
        (
            SyncRequest::VaultKey(vec![3]),
            (Method::POST, "/v2/vault/key".into(), Some(vec![3])),
        ),
        (
            SyncRequest::Telemetry(vec![4]),
            (
                Method::POST,
                "/v2/observability/events".into(),
                Some(vec![4]),
            ),
        ),
        (
            SyncRequest::NativeTraces(vec![5]),
            (
                Method::POST,
                "/v2/observability/traces".into(),
                Some(vec![5]),
            ),
        ),
    ] {
        assert!(!request.is_v3());
        assert_eq!(request.prepare().unwrap(), expected);
    }
}

#[test]
fn v3_original_receipt_and_encoded_page_limits_do_not_raise_the_transport_budget() {
    use http::StatusCode;
    use nddev_device_sync_domain::sync::{MAX_PAGE_BYTES, MAX_RESULT_BYTES};
    for path in [
        "/v3/sync/history?after_seq=7&limit=1",
        "/v3/sync/base?base_seq=7&after_member_seq=0&limit=1",
    ] {
        assert!(validate_v3_reply_size(path, StatusCode::OK, MAX_PAGE_BYTES).is_ok());
        assert_eq!(
            validate_v3_reply_size(path, StatusCode::OK, MAX_PAGE_BYTES + 1),
            Err(ClientError::InvalidResponse)
        );
    }
    for status in [StatusCode::CREATED, StatusCode::CONFLICT] {
        assert!(validate_v3_reply_size("/v3/sync/operations", status, MAX_RESULT_BYTES).is_ok());
        assert_eq!(
            validate_v3_reply_size("/v3/sync/operations", status, MAX_RESULT_BYTES + 1),
            Err(ClientError::InvalidResponse)
        );
    }
    // V2 decoding and the telemetry envelope retain their existing64KiB bound.
    assert!(
        validate_v3_reply_size("/v2/sync/operations", StatusCode::CONFLICT, crate::MAX_BODY)
            .is_ok()
    );
    assert!(
        validate_v3_reply_size("/v2/observability/events", StatusCode::OK, crate::MAX_BODY).is_ok()
    );
}

#[test]
fn diagnostic_requests_use_fixed_routes_and_bounded_bodies() {
    use http::Method;
    let (method, path, body) = SyncRequest::CollectionPolicy.prepare().unwrap();
    assert_eq!(
        (method, path.as_str(), body),
        (Method::GET, "/v2/observability/collection-policy", None)
    );
    let (method, path, body) = SyncRequest::GlobalDiagnosticChallenge.prepare().unwrap();
    assert_eq!(
        (method, path.as_str(), body),
        (Method::POST, "/v2/observability/global-challenge", None)
    );
    let (method, path, _) = SyncRequest::DiagnosticSearch(b"{}".to_vec())
        .prepare()
        .unwrap();
    assert_eq!(
        (method, path.as_str()),
        (Method::POST, "/v2/observability/search")
    );
    let (method, path, _) = SyncRequest::GlobalDiagnosticGrant(b"{}".to_vec())
        .prepare()
        .unwrap();
    assert_eq!(
        (method, path.as_str()),
        (Method::POST, "/v2/observability/global-grant")
    );
    for request in [
        SyncRequest::DiagnosticSearch(Vec::new()),
        SyncRequest::DiagnosticSearch(vec![b' '; 8193]),
        SyncRequest::GlobalDiagnosticGrant(Vec::new()),
        SyncRequest::GlobalDiagnosticGrant(vec![b' '; 4097]),
    ] {
        assert!(matches!(request.prepare(), Err(ClientError::InvalidInput)));
    }
    // Only a search page may exceed the ordinary reply bound.
    assert_eq!(crate::reply_limit("/v2/observability/search"), 1_048_576);
    assert_eq!(
        crate::reply_limit("/v2/observability/collection-policy"),
        65_536
    );
}
