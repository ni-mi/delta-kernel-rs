//! Caller-supplied cloud storage credentials that the engine refreshes as they expire.
//!
//! A connector that holds its own credentials — vended by a catalog, say — registers a callback
//! rather than a value, because those credentials are short-lived and a store built from a fixed
//! one stops working partway through a long read. The kernel invokes the callback when it needs a
//! credential and caches the result for the reported TTL.

use std::mem::MaybeUninit;
use std::ptr;
use std::sync::Arc;
use std::time::Duration;

use delta_kernel::object_store::ObjectStore;
use delta_kernel::{DeltaResult, Error};
use delta_kernel_default_engine::credentials::{CredentialSource, StorageCredential};
use delta_kernel_default_engine::storage::store_from_url_with_credentials;
use derive_more::Constructor;
use url::Url;

use crate::error::AllocateErrorFn;
use crate::{ExclusiveRustString, Handle, NullableCvoid, OptionalValue};

/// Which credential a [`CStorageCredential`] carries, and therefore which of its fields are read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub enum CStorageCredentialKind {
    /// No credential was produced. Report this when the callback cannot obtain one; the read
    /// that triggered the refresh fails rather than retrying with a stale credential.
    None = 0,
    /// AWS access key pair in `key_id` and `secret`, with a session token in `token` when the
    /// credential is temporary.
    AwsAccessKey,
    /// Google Cloud Storage OAuth bearer token in `token`.
    GcpBearerToken,
    /// Azure shared access signature in `token`, as the raw query string.
    AzureSasToken,
    /// Azure Entra ID bearer token in `token`.
    AzureBearerToken,
    /// Azure storage account shared key in `secret`, base64 encoded.
    AzureAccessKey,
}

/// Output buffer for a [`CStorageCredentialCallback`] invocation.
///
/// The kernel initializes every field before invoking the callback: `kind` to
/// [`CStorageCredentialKind::None`], each string to [`OptionalValue::None`], and `ttl_ms` to `0`.
/// Set `kind`, then the fields that kind documents, each via
/// [`allocate_kernel_string`](crate::allocate_kernel_string); ownership transfers to the kernel
/// when the callback returns. Fields left unset are not read.
#[repr(C)]
pub struct CStorageCredential {
    pub kind: CStorageCredentialKind,
    pub key_id: OptionalValue<Handle<ExclusiveRustString>>,
    pub secret: OptionalValue<Handle<ExclusiveRustString>>,
    pub token: OptionalValue<Handle<ExclusiveRustString>>,
    /// How long (in milliseconds) the credential stays valid. `0` means unknown, which makes the
    /// kernel invoke the callback again for every request.
    pub ttl_ms: u64,
}

/// Supplies the current storage credential for a cloud-backed engine.
///
/// The kernel invokes this when it needs a credential: once while building the store, and again
/// whenever the cached one is close to its reported expiry. `context` is the opaque pointer
/// registered alongside the callback, and `allocate_error` is forwarded so the callback can pass
/// it to [`allocate_kernel_string`](crate::allocate_kernel_string).
pub type CStorageCredentialCallback = extern "C" fn(
    context: NullableCvoid,
    out: *mut CStorageCredential,
    allocate_error: AllocateErrorFn,
);

/// Upcalls a [`CStorageCredentialCallback`] whenever the engine needs a storage credential.
#[derive(Clone, Copy, Constructor)]
pub(crate) struct FfiCredentialProvider {
    callback: CStorageCredentialCallback,
    context: NullableCvoid,
    allocate_error: AllocateErrorFn,
}
// SAFETY: see `set_builder_storage_credential_callback`: `context` and `callback` must be safe to
// invoke from any thread concurrently.
unsafe impl Send for FfiCredentialProvider {}
unsafe impl Sync for FfiCredentialProvider {}

impl FfiCredentialProvider {
    /// Invoke the callback and convert what it wrote into a credential and its TTL.
    pub(crate) fn collect(&self) -> DeltaResult<(StorageCredential, Option<Duration>)> {
        let mut slot = MaybeUninit::<CStorageCredential>::uninit();
        let out = slot.as_mut_ptr();
        // SAFETY: `out` is valid for writes, and every field is initialized before the callback
        // runs, so one that sets only some fields still leaves valid values behind. Each string
        // is taken exactly once, before any early return, so nothing the callback allocated
        // leaks when the credential itself is rejected.
        unsafe {
            ptr::write(ptr::addr_of_mut!((*out).kind), CStorageCredentialKind::None);
            ptr::write(ptr::addr_of_mut!((*out).key_id), OptionalValue::None);
            ptr::write(ptr::addr_of_mut!((*out).secret), OptionalValue::None);
            ptr::write(ptr::addr_of_mut!((*out).token), OptionalValue::None);
            ptr::write(ptr::addr_of_mut!((*out).ttl_ms), 0);

            (self.callback)(self.context, out, self.allocate_error);

            let ttl = ((*out).ttl_ms != 0).then(|| Duration::from_millis((*out).ttl_ms));
            let key_id = take_string(ptr::addr_of_mut!((*out).key_id));
            let secret = take_string(ptr::addr_of_mut!((*out).secret));
            let token = take_string(ptr::addr_of_mut!((*out).token));

            let credential = match (*out).kind {
                CStorageCredentialKind::None => {
                    return Err(Error::generic(
                        "storage credential callback produced no credential",
                    ))
                }
                CStorageCredentialKind::AwsAccessKey => StorageCredential::Aws {
                    key_id: key_id.ok_or_else(|| missing_field("key_id", "AwsAccessKey"))?,
                    secret: secret.ok_or_else(|| missing_field("secret", "AwsAccessKey"))?,
                    session_token: token,
                },
                CStorageCredentialKind::GcpBearerToken => StorageCredential::GcpBearer(
                    token.ok_or_else(|| missing_field("token", "GcpBearerToken"))?,
                ),
                CStorageCredentialKind::AzureSasToken => StorageCredential::AzureSas(
                    token.ok_or_else(|| missing_field("token", "AzureSasToken"))?,
                ),
                CStorageCredentialKind::AzureBearerToken => StorageCredential::AzureBearer(
                    token.ok_or_else(|| missing_field("token", "AzureBearerToken"))?,
                ),
                CStorageCredentialKind::AzureAccessKey => StorageCredential::AzureAccessKey(
                    secret.ok_or_else(|| missing_field("secret", "AzureAccessKey"))?,
                ),
            };
            Ok((credential, ttl))
        }
    }
}

/// Take ownership of an optional string the callback wrote, leaving [`OptionalValue::None`].
///
/// # Safety
///
/// `field` must point at an initialized `OptionalValue<Handle<ExclusiveRustString>>` whose
/// `Some` payload, if any, came from
/// [`allocate_kernel_string`](crate::allocate_kernel_string).
unsafe fn take_string(field: *mut OptionalValue<Handle<ExclusiveRustString>>) -> Option<String> {
    match ptr::replace(field, OptionalValue::None) {
        OptionalValue::Some(handle) => Some(*handle.into_inner()),
        OptionalValue::None => None,
    }
}

/// Build a cloud store for `url` whose credential comes from `provider` and is refreshed as it
/// expires.
pub(crate) fn store_from_credential_callback<I, K, V>(
    url: &Url,
    options: I,
    provider: FfiCredentialProvider,
) -> DeltaResult<Arc<dyn ObjectStore>>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: Into<String>,
{
    let source = Arc::new(CredentialSource::new(move || provider.collect()));
    store_from_url_with_credentials(url, options, source)
}

/// A credential whose kind requires a field the callback left unset.
fn missing_field(field: &str, kind: &str) -> Error {
    Error::generic(format!("storage credential of kind {kind} has no {field}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{EngineError, KernelError};
    use crate::KernelStringSlice;

    extern "C" fn allocate_err(etype: KernelError, _: KernelStringSlice) -> *mut EngineError {
        let boxed = Box::new(EngineError { etype });
        Box::leak(boxed)
    }

    fn test_allocate_error() -> AllocateErrorFn {
        allocate_err
    }

    fn provider(callback: CStorageCredentialCallback) -> FfiCredentialProvider {
        FfiCredentialProvider::new(callback, None, test_allocate_error())
    }

    fn set_string(field: *mut OptionalValue<Handle<ExclusiveRustString>>, value: &str) {
        unsafe {
            ptr::write(
                field,
                OptionalValue::Some(Box::new(value.to_string()).into()),
            )
        }
    }

    extern "C" fn fill_gcp_bearer(
        _: NullableCvoid,
        out: *mut CStorageCredential,
        _: AllocateErrorFn,
    ) {
        unsafe {
            (*out).kind = CStorageCredentialKind::GcpBearerToken;
            set_string(ptr::addr_of_mut!((*out).token), "ya29.example");
            (*out).ttl_ms = 60_000;
        }
    }

    extern "C" fn fill_nothing(_: NullableCvoid, _: *mut CStorageCredential, _: AllocateErrorFn) {}

    extern "C" fn fill_gcp_without_token(
        _: NullableCvoid,
        out: *mut CStorageCredential,
        _: AllocateErrorFn,
    ) {
        unsafe { (*out).kind = CStorageCredentialKind::GcpBearerToken }
    }

    #[test]
    fn a_callback_backed_gcs_store_is_built_from_its_url() {
        let url = Url::parse("gs://some-bucket/some-table").expect("parse url");
        let store = store_from_credential_callback(
            &url,
            std::iter::empty::<(&str, &str)>(),
            provider(fill_gcp_bearer),
        )
        .expect("build store");

        assert!(store.to_string().contains("GoogleCloudStorage"), "{store}");
    }

    #[test]
    fn a_callback_producing_the_wrong_cloud_fails_at_construction() {
        let url = Url::parse("s3://some-bucket/some-table").expect("parse url");
        store_from_credential_callback(&url, [("region", "us-east-1")], provider(fill_gcp_bearer))
            .expect_err("a GCP credential must not build an S3 store");
    }

    #[test]
    fn callback_supplies_a_gcp_bearer_token_and_its_ttl() {
        let (credential, ttl) = provider(fill_gcp_bearer).collect().expect("collect");

        assert!(matches!(
            credential,
            StorageCredential::GcpBearer(ref token) if token == "ya29.example"
        ));
        assert_eq!(ttl, Some(Duration::from_millis(60_000)));
    }

    #[test]
    fn a_callback_that_produces_nothing_is_an_error() {
        provider(fill_nothing)
            .collect()
            .expect_err("a callback that sets no kind must not yield a credential");
    }

    #[test]
    fn a_kind_missing_its_required_field_is_an_error() {
        provider(fill_gcp_without_token)
            .collect()
            .expect_err("a bearer kind with no token must be rejected");
    }
}
