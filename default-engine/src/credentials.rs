//! Caller-supplied cloud storage credentials that the engine can refresh.
//!
//! Credentials vended by a catalog are short-lived, so a store built from a fixed credential
//! stops working partway through a long read. A caller registers a closure here instead of a
//! value; the engine calls it when it needs a credential and caches the result until shortly
//! before the caller-reported expiry.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use delta_kernel::object_store::aws::AwsCredential;
use delta_kernel::object_store::azure::{AzureAccessKey, AzureCredential};
use delta_kernel::object_store::gcp::GcpCredential;
use delta_kernel::object_store::{
    CredentialProvider, Error as ObjectStoreError, Result as ObjectStoreResult,
};
use delta_kernel::{DeltaResult, Error as DeltaError};
use percent_encoding::percent_decode_str;

/// A cloud storage credential, in whichever shape its cloud uses.
///
/// AWS and Azure shared-key sign each request, so they carry signing material; the remaining
/// variants carry a credential the service issued and the client only presents.
#[derive(Clone)]
pub enum StorageCredential {
    /// Access key pair, with a session token when the credential is temporary.
    Aws {
        key_id: String,
        secret: String,
        session_token: Option<String>,
    },
    /// OAuth bearer token for Google Cloud Storage.
    GcpBearer(String),
    /// Azure shared access signature, as the raw query string.
    AzureSas(String),
    /// Azure Entra ID bearer token.
    AzureBearer(String),
    /// Azure storage account shared key, base64 encoded.
    AzureAccessKey(String),
}

/// Produces the current credential and how long it stays valid. `None` means unknown, in which
/// case it is never cached.
type ProduceCredential =
    Box<dyn Fn() -> DeltaResult<(StorageCredential, Option<Duration>)> + Send + Sync>;

/// How far before a credential's reported expiry to produce a fresh one, so a request never
/// signs with a credential that expires in flight.
const CREDENTIAL_REFRESH_BUFFER: Duration = Duration::from_secs(30);

/// Calls a caller-supplied closure for credentials, caching each one until shortly before it
/// expires.
pub struct CredentialSource {
    produce: ProduceCredential,
    cached: Mutex<Option<(StorageCredential, Instant)>>,
}

impl std::fmt::Debug for CredentialSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialSource").finish_non_exhaustive()
    }
}

impl CredentialSource {
    /// Create a source that calls `produce` when it needs a credential.
    pub fn new(
        produce: impl Fn() -> DeltaResult<(StorageCredential, Option<Duration>)> + Send + Sync + 'static,
    ) -> Self {
        Self {
            produce: Box::new(produce),
            cached: Mutex::new(None),
        }
    }

    /// The current credential, produced afresh if the cached one is absent or near expiry.
    pub fn current(&self) -> DeltaResult<StorageCredential> {
        // Hold the lock across the (rare) produce call so concurrent refreshes are single-flight.
        let mut cached = self.cached.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((credential, deadline)) = cached.as_ref() {
            if deadline.saturating_duration_since(Instant::now()) > CREDENTIAL_REFRESH_BUFFER {
                return Ok(credential.clone());
            }
        }
        let (credential, ttl) = (self.produce)()?;
        // Skip caching if an absurd TTL overflows `Instant`, rather than panicking.
        *cached = ttl.and_then(|ttl| Some((credential.clone(), Instant::now().checked_add(ttl)?)));
        Ok(credential)
    }
}

impl StorageCredential {
    /// The cloud this credential authenticates to, for reporting a mismatch against a URL.
    pub(crate) fn cloud(&self) -> &'static str {
        match self {
            Self::Aws { .. } => "AWS",
            Self::GcpBearer(_) => "GCP",
            Self::AzureSas(_) | Self::AzureBearer(_) | Self::AzureAccessKey(_) => "Azure",
        }
    }
}

/// A credential for the wrong cloud, named against the URL scheme that asked for it.
pub(crate) fn wrong_cloud(
    credential: &StorageCredential,
    scheme: &str,
    wanted: &str,
) -> DeltaError {
    DeltaError::generic(format!(
        "storage credential is for {}, but the table URL scheme `{scheme}` needs a {wanted} credential",
        credential.cloud()
    ))
}

/// Report a credential failure through the object store, which is what the caller sees when a
/// refresh fails partway through a read.
fn credential_error(error: impl std::fmt::Display) -> ObjectStoreError {
    ObjectStoreError::Generic {
        store: "StorageCredential",
        source: error.to_string().into(),
    }
}

/// Split a shared access signature into the query pairs the Azure store signs with.
///
/// Mirrors object_store's own handling: the whole string is percent-decoded first, so a `+` in a
/// base64 signature stays a `+` rather than becoming a space as form decoding would make it.
pub(crate) fn split_sas(sas: &str) -> DeltaResult<Vec<(String, String)>> {
    let sas = percent_decode_str(sas).decode_utf8().map_err(|source| {
        DeltaError::generic(format!("shared access signature is not utf-8: {source}"))
    })?;
    sas.trim_start_matches('?')
        .split('&')
        .filter(|pair| !pair.chars().all(char::is_whitespace))
        .map(|pair| {
            pair.trim()
                .split_once('=')
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .ok_or_else(|| {
                    DeltaError::generic("shared access signature has a component without a value")
                })
        })
        .collect()
}

/// A refreshed credential that no longer matches the store it belongs to. Construction rejects a
/// mismatched credential up front, so this only fires if a later refresh returns a different cloud.
fn cloud_changed(credential: &StorageCredential, wanted: &str) -> ObjectStoreError {
    credential_error(format!(
        "refreshed storage credential is for {}, but this store needs a {wanted} credential",
        credential.cloud()
    ))
}

/// Adapts a [`CredentialSource`] to the credential type the S3 store expects.
#[derive(Debug)]
pub(crate) struct AwsCredentials(pub(crate) Arc<CredentialSource>);

#[async_trait]
impl CredentialProvider for AwsCredentials {
    type Credential = AwsCredential;

    async fn get_credential(&self) -> ObjectStoreResult<Arc<AwsCredential>> {
        match self.0.current().map_err(credential_error)? {
            StorageCredential::Aws {
                key_id,
                secret,
                session_token,
            } => Ok(Arc::new(AwsCredential {
                key_id,
                secret_key: secret,
                token: session_token,
            })),
            other => Err(cloud_changed(&other, "AWS")),
        }
    }
}

/// Adapts a [`CredentialSource`] to the credential type the GCS store expects.
#[derive(Debug)]
pub(crate) struct GcpCredentials(pub(crate) Arc<CredentialSource>);

#[async_trait]
impl CredentialProvider for GcpCredentials {
    type Credential = GcpCredential;

    async fn get_credential(&self) -> ObjectStoreResult<Arc<GcpCredential>> {
        match self.0.current().map_err(credential_error)? {
            StorageCredential::GcpBearer(bearer) => Ok(Arc::new(GcpCredential { bearer })),
            other => Err(cloud_changed(&other, "GCP")),
        }
    }
}

/// Adapts a [`CredentialSource`] to the credential type the Azure store expects.
#[derive(Debug)]
pub(crate) struct AzureCredentials(pub(crate) Arc<CredentialSource>);

#[async_trait]
impl CredentialProvider for AzureCredentials {
    type Credential = AzureCredential;

    async fn get_credential(&self) -> ObjectStoreResult<Arc<AzureCredential>> {
        let credential = match self.0.current().map_err(credential_error)? {
            StorageCredential::AzureSas(sas) => {
                AzureCredential::SASToken(split_sas(&sas).map_err(credential_error)?)
            }
            StorageCredential::AzureBearer(token) => AzureCredential::BearerToken(token),
            StorageCredential::AzureAccessKey(key) => {
                AzureCredential::AccessKey(AzureAccessKey::try_new(&key).map_err(credential_error)?)
            }
            other => return Err(cloud_changed(&other, "Azure")),
        };
        Ok(Arc::new(credential))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;

    /// A source whose closure records how many times it ran, so tests can assert on caching.
    fn counting_source(ttl: Option<Duration>) -> (CredentialSource, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let source = CredentialSource::new(move || {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            Ok((StorageCredential::GcpBearer(format!("token-{n}")), ttl))
        });
        (source, calls)
    }

    #[test]
    fn splitting_a_sas_preserves_plus_in_a_signature() {
        // A base64 signature routinely contains `+`. Form decoding would turn it into a space and
        // silently invalidate the signature, so this asserts percent-decoding semantics instead.
        let pairs = split_sas("?sv=2021-01-01&sig=ab%2Bcd+ef&se=2026-01-01T00%3A00%3A00Z")
            .expect("split sas");

        assert_eq!(
            pairs,
            vec![
                ("sv".to_string(), "2021-01-01".to_string()),
                ("sig".to_string(), "ab+cd+ef".to_string()),
                ("se".to_string(), "2026-01-01T00:00:00Z".to_string()),
            ]
        );
    }

    #[test]
    fn splitting_a_sas_without_a_value_is_an_error() {
        split_sas("sv=2021-01-01&malformed").expect_err("pair without `=` must be rejected");
    }

    #[test]
    fn credential_is_produced_once_and_reused_while_valid() {
        let (source, calls) = counting_source(Some(Duration::from_secs(3600)));

        source.current().expect("first credential");
        source.current().expect("second credential");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
