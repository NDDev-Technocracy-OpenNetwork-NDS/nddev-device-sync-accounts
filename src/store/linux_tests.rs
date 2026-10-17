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
