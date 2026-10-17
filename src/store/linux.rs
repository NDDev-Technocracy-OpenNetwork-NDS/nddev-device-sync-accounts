//! Native Secret Service I/O. All calls run under SessionStore's owned I/O permit.
use crate::ClientError;
use glib::translate::*;
use libsecret::{Item, Schema, Service, Value, prelude::*};
use std::{collections::HashMap, ptr};
use zeroize::Zeroizing;

pub(super) fn with_entry<T>(
    service: &str,
    key: &str,
    action: impl FnOnce(Entry) -> Result<T, ClientError>,
) -> Result<T, ClientError> {
    let result = Entry::new(service, key).and_then(action);
    if result.is_err() {
        // Discard the native library's cached proxy, not credential values.
        // Existing users retain their references. Never replay an uncertain write.
        Service::disconnect();
    }
    result
}

pub(super) struct Entry {
    service: Service,
    schema: Schema,
    attributes: HashMap<String, String>,
}

impl Entry {
    fn new(service: &str, key: &str) -> Result<Self, ClientError> {
        let native = Service::sync(
            libsecret::ServiceFlags::OPEN_SESSION,
            gio::Cancellable::NONE,
        )
        .map_err(|_| ClientError::CredentialStore)?;
        // libsecret can negotiate plain transport with a limited provider. NDS
        // requires encryption and rejects that fallback before accessing secrets.
        if native.session_algorithms().as_deref() != Some("dh-ietf1024-sha256-aes128-cbc-pkcs7") {
            return Err(ClientError::CredentialStore);
        }
        Ok(Self {
            service: native,
            schema: Schema::new(
                "ai.nddev.nds",
                libsecret::SchemaFlags::DONT_MATCH_NAME,
                HashMap::from([
                    ("service", libsecret::SchemaAttributeType::String),
                    ("username", libsecret::SchemaAttributeType::String),
                ]),
            ),
            // Preserve the previous provider's exact lookup across collections.
            attributes: HashMap::from([
                ("service".into(), service.into()),
                ("username".into(), key.into()),
            ]),
        })
    }

    fn find(&self) -> Result<Option<Item>, ClientError> {
        // SAFETY: all borrowed objects outlive the synchronous call. The owned
        // attribute table is released once; the full-transfer list/items and
        // optional GError are adopted exactly once, including failure paths.
        let items: Vec<Item> = unsafe {
            let attributes = self.attributes.to_glib_full();
            let mut error = ptr::null_mut();
            let items = libsecret::ffi::secret_service_search_sync(
                self.service.to_glib_none().0,
                self.schema.to_glib_none().0,
                attributes,
                (libsecret::SearchFlags::ALL | libsecret::SearchFlags::UNLOCK).into_glib(),
                ptr::null_mut(),
                &mut error,
            );
            glib::ffi::g_hash_table_unref(attributes);
            let items = FromGlibPtrContainer::from_glib_full(items);
            checked(error)?;
            items
        };
        // A declined unlock is not absence. Never choose one ambiguous record
        // or overwrite/delete several credentials sharing a lookup.
        match items.as_slice() {
            [] => Ok(None),
            [item] if !item.is_locked() => Ok(Some(item.clone())),
            _ => Err(ClientError::CredentialStore),
        }
    }

    pub(super) fn read(self) -> Result<Option<Zeroizing<Vec<u8>>>, ClientError> {
        let Some(item) = self.find()? else {
            return Ok(None);
        };
        item.load_secret_sync(gio::Cancellable::NONE)
            .map_err(|_| ClientError::CredentialStore)?;
        let value = item.secret().ok_or(ClientError::CredentialStore)?;
        Ok(Some(Zeroizing::new(value.get().to_vec())))
    }

    pub(super) fn write(self, bytes: &[u8]) -> Result<(), ClientError> {
        let length = isize::try_from(bytes.len()).map_err(|_| ClientError::CredentialStore)?;
        // SAFETY: libsecret copies exactly length bytes during this call. The
        // input remains alive; the non-null returned value transfers ownership.
        // Its native destructor clears secret storage. Arbitrary binary keys
        // must not be converted to UTF-8 or re-encoded during this transition.
        let value: Value = unsafe {
            let value = libsecret::ffi::secret_value_new(
                bytes.as_ptr().cast(),
                length,
                c"application/octet-stream".as_ptr(),
            );
            if value.is_null() {
                return Err(ClientError::CredentialStore);
            }
            from_glib_full(value)
        };
        if let Some(item) = self.find()? {
            return item
                .set_secret_sync(&value, gio::Cancellable::NONE)
                .map_err(|_| ClientError::CredentialStore);
        }
        // SAFETY: synchronous borrowed inputs remain valid; the attribute table
        // and GError follow the same ownership rules as search above. A null
        // collection selects the persistent default collection, never a file
        // backend or the transient session collection.
        unsafe {
            let attributes = self.attributes.to_glib_full();
            let mut error = ptr::null_mut();
            let stored = libsecret::ffi::secret_service_store_sync(
                self.service.to_glib_none().0,
                self.schema.to_glib_none().0,
                attributes,
                ptr::null(),
                c"NDS credential".as_ptr(),
                value.to_glib_none().0,
                ptr::null_mut(),
                &mut error,
            );
            glib::ffi::g_hash_table_unref(attributes);
            checked(error)?;
            if stored == glib::ffi::GFALSE {
                return Err(ClientError::CredentialStore);
            }
        }
        Ok(())
    }

    pub(super) fn delete(self) -> Result<(), ClientError> {
        if let Some(item) = self.find()? {
            item.delete_sync(gio::Cancellable::NONE)
                .map_err(|_| ClientError::CredentialStore)?;
        }
        Ok(())
    }
}

// SAFETY: callers pass only a full-transfer GError produced by libsecret.
unsafe fn checked(error: *mut glib::ffi::GError) -> Result<(), ClientError> {
    if error.is_null() {
        return Ok(());
    }
    // Provider text may contain identifiers. Free it without exposing/logging it.
    drop(unsafe { from_glib_full::<_, glib::Error>(error) });
    Err(ClientError::CredentialStore)
}

#[cfg(test)]
#[path = "linux_tests.rs"]
mod tests;
