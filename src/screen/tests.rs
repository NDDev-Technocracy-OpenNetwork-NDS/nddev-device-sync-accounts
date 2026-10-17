use super::*;

fn key(seed: u8) -> String {
    URL_SAFE_NO_PAD.encode(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .as_bytes(),
    )
}
fn row() -> dto::ScreenView {
    dto::ScreenView {
        admitted_at_ms: 1000,
        expires_at_ms: 3000,
        display: 0,
        max_fps: 30,
        output_height: 480,
        viewer_device_id: "viewer".into(),
        host_device_id: "host".into(),
        viewer_endpoint: key(1),
        host_endpoint: key(2),
        viewer_revision: 1,
        host_revision: 2,
        view_id: "view-1".into(),
        state: dto::State::Ready,
    }
}
#[test]
fn restored_projection_preserves_original_expiry_and_rejects_identity_confusion() {
    let mut view = projection(row()).unwrap();
    assert_eq!(view.permit().lease.admitted_at_ms(), 1000);
    assert_eq!(view.state(4000), ViewState::Ended);
    for field in ["device", "key", "revision", "lease", "path"] {
        let mut row = row();
        match field {
            "device" => row.host_device_id = row.viewer_device_id.clone(),
            "key" => row.host_endpoint = row.viewer_endpoint.clone(),
            "revision" => row.viewer_revision = 0,
            "lease" => row.expires_at_ms = MAX_REVISION as i64,
            "path" => row.view_id = "view/foreign".into(),
            _ => unreachable!(),
        }
        assert!(matches!(projection(row), Err(ClientError::InvalidResponse)));
    }
}
#[test]
fn endpoint_metadata_requires_canonical_strong_key_and_instance() {
    let seed = SigningKey::from_bytes(&[1; 32]);
    let instance = uuid::Uuid::new_v4();
    let row = || dto::ScreenBinding {
        device_id: "viewer".into(),
        endpoint_public_key: URL_SAFE_NO_PAD.encode(seed.verifying_key().as_bytes()),
        instance_id: instance.to_string(),
        revision: 1,
    };
    assert!(binding(row()).is_ok());
    for value in [
        uuid::Uuid::nil().to_string(),
        instance.to_string().to_uppercase(),
    ] {
        let mut wrong = row();
        wrong.instance_id = value;
        assert!(matches!(binding(wrong), Err(ClientError::InvalidResponse)));
    }
    let mut weak = [0u8; 32];
    weak[0] = 1;
    for value in [
        URL_SAFE_NO_PAD.encode(weak),
        format!("{}=", row().endpoint_public_key),
    ] {
        let mut wrong = row();
        wrong.endpoint_public_key = value;
        assert!(matches!(binding(wrong), Err(ClientError::InvalidResponse)));
    }
}
#[test]
fn exact_empty_end_and_sensitive_artifact_bounds_survive_mapping() {
    let context = crate::sync::SigningContext {
        device: DeviceId::new("viewer").unwrap(),
        nonce: "fresh_nonce_value".into(),
        created: 1,
        now_ms: 1000,
        expires_at_ms: 61000,
        session_expires_at_ms: 100000,
    };
    let (method, path, body, status) = Request::End("view-1")
        .prepare("https://example.invalid", &context)
        .unwrap();
    assert_eq!(method, http::Method::POST);
    assert_eq!(path, "/v2/rds/views/view-1/end");
    assert!(body.is_none());
    assert_eq!(status, 204);
    for id in ["", "view/foreign", "view?token=private", "view#fragment"] {
        assert!(matches!(
            Request::View(id).prepare("https://example.invalid", &context),
            Err(ClientError::InvalidInput)
        ));
    }
    assert!(matches!(
        ScreenArtifact::new(&[]),
        Err(ClientError::InvalidInput)
    ));
    assert!(matches!(
        ScreenArtifact::new(&vec![0; 8193]),
        Err(ClientError::InvalidInput)
    ));
    let artifact = ScreenArtifact::new(&vec![7; 8192]).unwrap();
    let response: dto::ScreenReadyRequest = decode(&artifact.body().unwrap()).unwrap();
    assert_eq!(response.native_grant.len(), 10923);
    assert_eq!(
        URL_SAFE_NO_PAD.decode(response.native_grant).unwrap(),
        artifact.bytes()
    );
    assert!(decode::<dto::ScreenBindingResponse>(b"{}").is_err());
    assert!(decode::<dto::ScreenIncoming>(b"{}").is_err());
    assert!(decode::<dto::ScreenViewResponse>(b"{}").is_err());
    assert_eq!(
        route_template("/v2/rds/views/view-secret/ready"),
        Some("/v2/rds/views/{view_id}/ready")
    );
    assert_eq!(route_template("/v2/rds/views/incoming"), None);
}
#[test]
fn original_create_bytes_and_profile_do_not_change_during_retry() {
    let request = dto::ScreenViewRequest {
        display: 0,
        expires_at_ms: 3000,
        host_revision: 1,
        idempotency_key: "a".repeat(256),
        max_fps: 30,
        output_height: 480,
        target_device_id: "host".into(),
        viewer_revision: 1,
    };
    let create = ScreenCreate::new(request).unwrap();
    let context = |nonce: &str| crate::sync::SigningContext {
        device: DeviceId::new("viewer").unwrap(),
        nonce: nonce.into(),
        created: 1,
        now_ms: 1000,
        expires_at_ms: 61000,
        session_expires_at_ms: 100000,
    };
    let a = Request::Create(&create)
        .prepare("https://example.invalid", &context("nonce_first"))
        .unwrap()
        .2;
    let b = Request::Create(&create)
        .prepare("https://example.invalid", &context("nonce_second"))
        .unwrap()
        .2;
    assert_eq!(a, b);
    let mut wrong = create.request.clone();
    wrong.idempotency_key.push('a');
    assert!(matches!(
        ScreenCreate::new(wrong),
        Err(ClientError::InvalidInput)
    ));
    let mut changed = projection(row()).unwrap();
    let original = changed.clone();
    changed.end();
    assert!(same_view(&original, &changed));
    let mut wrong = row();
    wrong.expires_at_ms = 4000;
    assert!(!same_view(&original, &projection(wrong).unwrap()));
}

#[test]
fn live_revalidation_never_renews_or_substitutes_an_admitted_view() {
    let original = projection(row()).unwrap();
    assert_eq!(
        current_view(&original, Some(projection(row()).unwrap()), 1500),
        Ok(true)
    );
    assert_eq!(current_view(&original, None, 1500), Ok(false));
    assert_eq!(
        current_view(&original, Some(projection(row()).unwrap()), 3000),
        Ok(false)
    );
    for state in [dto::State::Requested, dto::State::Ended] {
        let mut current = row();
        current.state = state;
        assert_eq!(
            current_view(&original, Some(projection(current).unwrap()), 1500),
            Ok(false)
        );
    }
    for field in [
        "view", "viewer", "host", "endpoint", "revision", "expiry", "profile",
    ] {
        let mut current = row();
        match field {
            "view" => current.view_id = "another-view".into(),
            "viewer" => current.viewer_device_id = "another-viewer".into(),
            "host" => current.host_device_id = "another-host".into(),
            "endpoint" => current.host_endpoint = key(3),
            "revision" => current.host_revision += 1,
            "expiry" => current.expires_at_ms += 1000,
            "profile" => current.output_height = 720,
            _ => unreachable!(),
        }
        assert!(matches!(
            current_view(&original, Some(projection(current).unwrap()), 1500),
            Err(ClientError::InvalidResponse)
        ));
    }
}

#[test]
fn target_discovery_binds_selection_and_rejects_private_or_unbounded_metadata() {
    let user = UserId::new("member").unwrap();
    let row = || dto::ScreenTarget {
        device_id: "device-1".into(),
        display_name: "Owned device".into(),
        platform: dto::Platform::Linux,
        registered: false,
    };
    let page = || dto::ScreenTargetList {
        user_id: "member".into(),
        targets: vec![row()],
    };
    let values = targets(page(), &user).unwrap();
    assert_eq!(values.len(), 1);
    assert!(!values[0].registered);
    let mut foreign = page();
    foreign.user_id = "other".into();
    assert!(matches!(
        targets(foreign, &user),
        Err(ClientError::InvalidResponse)
    ));
    let mut duplicate = page();
    duplicate.targets.push(row());
    assert!(matches!(
        targets(duplicate, &user),
        Err(ClientError::InvalidResponse)
    ));
    let mut full = page();
    full.targets = (0..32)
        .map(|i| {
            let mut v = row();
            v.device_id = format!("device-{i}");
            v
        })
        .collect();
    assert_eq!(targets(full.clone(), &user).unwrap().len(), 32);
    let mut overflow = row();
    overflow.device_id = "device-32".into();
    full.targets.push(overflow);
    assert!(matches!(
        targets(full, &user),
        Err(ClientError::InvalidResponse)
    ));
    for name in ["", " leading", "trailing ", "control\nname"] {
        let mut wrong = page();
        wrong.targets[0].display_name = name.into();
        assert!(matches!(
            targets(wrong, &user),
            Err(ClientError::InvalidResponse)
        ));
    }
    assert!(decode::<dto::ScreenTargetList>(br#"{"user_id":"member","targets":[{"device_id":"device-1","display_name":"Owned","platform":"linux","registered":true,"public_key":"private"}]}"#).is_err());
    assert_eq!(
        route_template("/v2/rds/targets/member"),
        Some("/v2/rds/targets/{user_id}")
    );
    let context = crate::sync::SigningContext {
        device: DeviceId::new("viewer").unwrap(),
        nonce: "fresh_nonce_value".into(),
        created: 1,
        now_ms: 1000,
        expires_at_ms: 61000,
        session_expires_at_ms: 100000,
    };
    let (method, path, body, status) = Request::Targets(&user)
        .prepare("https://example.invalid", &context)
        .unwrap();
    assert_eq!(method, http::Method::GET);
    assert_eq!(path, "/v2/rds/targets/member");
    assert!(body.is_none());
    assert_eq!(status, 200);
}
