//! Real Secret Service acceptance; every test owns a fresh credential namespace.
use super::*;
use crate::SessionStore;
use glib::prelude::StaticType;

fn independent(service: &str, key: &str) -> Entry {
    let mut entry = Entry::new(service, key).unwrap();
    entry.service = Service::open_sync(
        Service::static_type(),
        None,
        libsecret::ServiceFlags::OPEN_SESSION,
        gio::Cancellable::NONE,
    )
    .unwrap();
    assert_eq!(
        entry.service.session_algorithms().as_deref(),
        Some("dh-ietf1024-sha256-aes128-cbc-pkcs7")
    );
    entry
}

#[tokio::test]
#[ignore = "requires an unlocked Secret Service; owns one fresh entry"]
async fn fresh_reads_observe_external_binary_updates_and_deletion() {
    let scope = format!("https://nds-native-{}.invalid/", uuid::Uuid::new_v4());
    let store = SessionStore::for_endpoint(&scope).unwrap();
    assert!(store.read().await.unwrap().is_none());
    let service = store.service;
    let key = store.key.clone();
    let outcome = async {
        store.write(&[]).await?;
        assert!(store.read().await?.unwrap().is_empty());
        let replacement = [0, 255, 128, 1, 0, 244];
        let other_key = key.clone();
        tokio::task::spawn_blocking(move || independent(service, &other_key).write(&replacement))
            .await
            .unwrap()?;
        assert_eq!(store.read().await?.unwrap().as_slice(), replacement);
        tokio::task::spawn_blocking(move || independent(service, &key).delete())
            .await
            .unwrap()?;
        assert!(store.read().await?.is_none());
        Ok::<_, ClientError>(())
    }
    .await;
    store.delete().await.unwrap();
    outcome.unwrap();
}

#[tokio::test]
#[ignore = "requires an isolated unlocked Secret Service without an application main loop"]
async fn repeated_reads_do_not_accumulate_unserviced_callbacks() {
    assert_eq!(std::env::var("NDS_ISOLATED_PROVIDER").as_deref(), Ok("1"));
    let scope = format!(
        "https://nds-native-lifetime-{}.invalid/",
        uuid::Uuid::new_v4()
    );
    let store = SessionStore::for_endpoint(&scope).unwrap();
    store.write(b"owned-lifetime-fixture").await.unwrap();
    let context = store
        .run_io("identity.credential.read", |_, _| {
            Ok(glib::MainContext::ref_thread_default())
        })
        .await
        .unwrap();
    let marker = || {
        let source = glib::source::idle_source_new(
            Some("owned-credential-lifetime-marker"),
            glib::Priority::DEFAULT,
            || glib::ControlFlow::Break,
        );
        let id = source.attach(Some(&context)).as_raw();
        source.destroy();
        id
    };
    let first = marker();
    let outcome = async {
        for _ in 0..128 {
            assert_eq!(
                store.read().await?.unwrap().as_slice(),
                b"owned-lifetime-fixture"
            );
        }
        Ok::<_, ClientError>(())
    }
    .await;
    store.delete().await.unwrap();
    outcome.unwrap();
    let last = marker();
    assert!((first..first + 100_000).contains(&last));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        let retained = (first + 1..last)
            .filter(|id| {
                // SAFETY: this test process owns the context; the bounded IDs
                // come from its actual attached markers. The borrowed pointer
                // is only tested for presence, never dereferenced or adopted.
                unsafe {
                    !glib::ffi::g_main_context_find_source_by_id(context.to_glib_none().0, *id)
                        .is_null()
                }
            })
            .count();
        if retained == 0 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "Native reads retained {retained} callbacks without an application main loop"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

struct OwnedItems(Vec<Item>);
impl Drop for OwnedItems {
    fn drop(&mut self) {
        for item in &self.0 {
            let _ = item.delete_sync(gio::Cancellable::NONE);
        }
    }
}

#[test]
#[ignore = "requires an unlocked Secret Service; owns two fresh ambiguous entries"]
fn ambiguous_records_are_never_read_overwritten_or_deleted() {
    let service = format!("ai.nddev.nds.test.{}", uuid::Uuid::new_v4());
    let key = "owned-ambiguity";
    let entry = independent(&service, key);
    let collection = libsecret::Collection::for_alias_sync(
        Some(&entry.service),
        "default",
        libsecret::CollectionFlags::NONE,
        gio::Cancellable::NONE,
    )
    .unwrap()
    .unwrap();
    let mut owned = OwnedItems(Vec::new());
    for value in ["owned-first", "owned-second"] {
        owned.0.push(
            Item::create_sync(
                &collection,
                Some(&entry.schema),
                HashMap::from([("service", service.as_str()), ("username", key)]),
                "NDS owned acceptance",
                &Value::new(value, "text/plain"),
                libsecret::ItemCreateFlags::NONE,
                gio::Cancellable::NONE,
            )
            .unwrap(),
        );
    }
    assert!(matches!(
        Entry::new(&service, key).unwrap().read(),
        Err(ClientError::CredentialStore)
    ));
    assert!(matches!(
        Entry::new(&service, key)
            .unwrap()
            .write(b"must-not-replace"),
        Err(ClientError::CredentialStore)
    ));
    assert!(matches!(
        Entry::new(&service, key).unwrap().delete(),
        Err(ClientError::CredentialStore)
    ));
    for (item, expected) in owned
        .0
        .iter()
        .zip([b"owned-first".as_slice(), b"owned-second"])
    {
        item.load_secret_sync(gio::Cancellable::NONE).unwrap();
        assert_eq!(item.secret().unwrap().get(), expected);
    }
    drop(owned);
    assert!(Entry::new(&service, key).unwrap().read().unwrap().is_none());
}
