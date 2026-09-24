use std::collections::HashMap;
use std::sync::{Arc, LazyLock, RwLock};

use delta_kernel::object_store::aws::{AmazonS3Builder, AmazonS3ConfigKey};
use delta_kernel::object_store::azure::{AzureConfigKey, MicrosoftAzureBuilder};
use delta_kernel::object_store::gcp::{GoogleCloudStorageBuilder, GoogleConfigKey};
use delta_kernel::object_store::path::Path;
use delta_kernel::object_store::{self, Error, ObjectStore, ObjectStoreScheme};
use delta_kernel::Error as DeltaError;
use url::Url;

use crate::credentials::{
    wrong_cloud, AwsCredentials, AzureCredentials, CredentialSource, GcpCredentials,
    StorageCredential,
};

/// Apply string options to a cloud store builder, skipping any the builder does not recognize.
/// Mirrors what [`store_from_url_opts`] gets from `object_store::parse_url_opts`.
macro_rules! apply_options {
    ($builder:expr, $options:expr, $key:ty) => {{
        let mut builder = $builder;
        for (key, value) in $options {
            if let Ok(key) = key.as_ref().parse::<$key>() {
                builder = builder.with_config(key, value);
            }
        }
        builder
    }};
}

/// Alias for convenience
type ClosureReturn = Result<(Box<dyn ObjectStore>, Path), Error>;
/// This type alias makes it easier to reference the handler closure(s)
///
/// It uses a HashMap<String, String> which _must_ be converted in [store_from_url_opts]
/// because we cannot use generics in this scenario.
type HandlerClosure = Arc<dyn Fn(&Url, HashMap<String, String>) -> ClosureReturn + Send + Sync>;
/// hashmap containing scheme => handler fn mappings to allow consumers of delta-kernel-rs provide
/// their own url opts parsers for different scemes
type Handlers = HashMap<String, HandlerClosure>;
/// The URL_REGISTRY contains the custom URL scheme handlers that will parse URL options
static URL_REGISTRY: LazyLock<RwLock<Handlers>> = LazyLock::new(|| RwLock::new(HashMap::default()));

/// Insert a new URL handler for [store_from_url_opts] with the given `scheme`. This allows
/// users to provide their own custom URL handler to plug new
/// [delta_kernel::object_store::ObjectStore] instances into delta-kernel, which is used by
/// [store_from_url_opts] to parse the URL.
pub fn insert_url_handler(
    scheme: impl AsRef<str>,
    handler_closure: HandlerClosure,
) -> Result<(), DeltaError> {
    let Ok(mut registry) = URL_REGISTRY.write() else {
        return Err(DeltaError::generic(
            "failed to acquire lock for adding a URL handler!",
        ));
    };
    registry.insert(scheme.as_ref().into(), handler_closure);
    Ok(())
}

/// Create an [`ObjectStore`] from a URL.
///
/// Returns an `Arc<dyn ObjectStore>` ready to use with [`crate::DefaultEngine`].
///
/// This function checks for custom URL handlers registered via [`insert_url_handler`]
/// before falling back to [`object_store`]'s default behavior.
///
/// # Example
///
/// ```rust
/// # use url::Url;
/// # use delta_kernel_default_engine::storage::store_from_url;
/// # use delta_kernel::DeltaResult;
/// # fn example() -> DeltaResult<()> {
/// let url = Url::parse("file:///path/to/table")?;
/// let store = store_from_url(&url)?;
/// # Ok(())
/// # }
/// ```
pub fn store_from_url(url: &Url) -> delta_kernel::DeltaResult<Arc<dyn ObjectStore>> {
    store_from_url_opts(url, std::iter::empty::<(&str, &str)>())
}

/// Create an [`ObjectStore`] from a URL with custom options.
///
/// Returns an `Arc<dyn ObjectStore>` ready to use with [`crate::DefaultEngine`].
///
/// This function checks for custom URL handlers registered via [`insert_url_handler`]
/// before falling back to [`object_store`]'s default behavior.
///
/// # Example
///
/// ```rust
/// # use url::Url;
/// # use std::collections::HashMap;
/// # use delta_kernel_default_engine::storage::store_from_url_opts;
/// # use delta_kernel::DeltaResult;
/// # fn example() -> DeltaResult<()> {
/// let url = Url::parse("s3://my-bucket/path/to/table")?;
/// let options = HashMap::from([("region", "us-west-2")]);
/// let store = store_from_url_opts(&url, options)?;
/// # Ok(())
/// # }
/// ```
pub fn store_from_url_opts<I, K, V>(
    url: &Url,
    options: I,
) -> delta_kernel::DeltaResult<Arc<dyn ObjectStore>>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: Into<String>,
{
    // First attempt to use any schemes registered via insert_url_handler,
    // falling back to the default behavior of delta_kernel::object_store::parse_url_opts
    let (store, _path) = if let Ok(handlers) = URL_REGISTRY.read() {
        if let Some(handler) = handlers.get(url.scheme()) {
            let options = options
                .into_iter()
                .map(|(k, v)| (k.as_ref().to_string(), v.into()))
                .collect();
            handler(url, options)?
        } else {
            object_store::parse_url_opts(url, options)?
        }
    } else {
        object_store::parse_url_opts(url, options)?
    };

    Ok(Arc::new(store))
}

/// Create an [`ObjectStore`] from a URL whose credential is supplied by `credentials` and
/// refreshed as it expires, rather than fixed in `options`.
///
/// The credential is produced once here so a credential that does not match the URL's cloud is
/// reported at construction rather than on the first request. Remaining `options` are applied as
/// they are by [`store_from_url_opts`]; a credential in `options` is ignored in favor of
/// `credentials`.
pub fn store_from_url_with_credentials<I, K, V>(
    url: &Url,
    options: I,
    credentials: Arc<CredentialSource>,
) -> delta_kernel::DeltaResult<Arc<dyn ObjectStore>>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: Into<String>,
{
    // Produce once up front so a credential for the wrong cloud is reported here rather than on
    // the first request, and so the store starts with a warm cache.
    let credential = credentials.current()?;
    let (scheme, _path) = ObjectStoreScheme::parse(url).map_err(Error::from)?;
    let store: Arc<dyn ObjectStore> = match scheme {
        ObjectStoreScheme::AmazonS3 => {
            if !matches!(credential, StorageCredential::Aws { .. }) {
                return Err(wrong_cloud(&credential, url.scheme(), "AWS"));
            }
            let builder = apply_options!(
                AmazonS3Builder::new().with_url(url.as_str()),
                options,
                AmazonS3ConfigKey
            );
            Arc::new(
                builder
                    .with_credentials(Arc::new(AwsCredentials(credentials)))
                    .build()?,
            )
        }
        ObjectStoreScheme::GoogleCloudStorage => {
            if !matches!(credential, StorageCredential::GcpBearer(_)) {
                return Err(wrong_cloud(&credential, url.scheme(), "GCP"));
            }
            let builder = apply_options!(
                GoogleCloudStorageBuilder::new().with_url(url.as_str()),
                options,
                GoogleConfigKey
            );
            Arc::new(
                builder
                    .with_credentials(Arc::new(GcpCredentials(credentials)))
                    .build()?,
            )
        }
        ObjectStoreScheme::MicrosoftAzure => {
            if credential.cloud() != "Azure" {
                return Err(wrong_cloud(&credential, url.scheme(), "Azure"));
            }
            let builder = apply_options!(
                MicrosoftAzureBuilder::new().with_url(url.as_str()),
                options,
                AzureConfigKey
            );
            Arc::new(
                builder
                    .with_credentials(Arc::new(AzureCredentials(credentials)))
                    .build()?,
            )
        }
        other => {
            return Err(DeltaError::generic(format!(
                "supplying storage credentials is not supported for {other:?} urls"
            )))
        }
    };
    Ok(store)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use delta_kernel::object_store::path::Path;
    use delta_kernel::object_store::{self, ObjectStore};
    use hdfs_native_object_store::HdfsObjectStoreBuilder;

    use super::{
        insert_url_handler, store_from_url_opts, store_from_url_with_credentials, URL_REGISTRY,
    };
    use crate::credentials::{CredentialSource, StorageCredential};
    use crate::*;

    fn fixed(credential: StorageCredential) -> Arc<CredentialSource> {
        Arc::new(CredentialSource::new(move || {
            Ok((credential.clone(), None))
        }))
    }

    #[test]
    fn gcs_url_builds_a_google_store_from_a_bearer_token() {
        let url = Url::parse("gs://some-bucket/some-table").expect("parse url");
        let store = store_from_url_with_credentials(
            &url,
            std::iter::empty::<(&str, &str)>(),
            fixed(StorageCredential::GcpBearer("ya29.example".into())),
        )
        .expect("build store");

        assert!(store.to_string().contains("GoogleCloudStorage"), "{store}");
    }

    #[test]
    fn s3_url_builds_an_amazon_store_from_an_access_key() {
        let url = Url::parse("s3://some-bucket/some-table").expect("parse url");
        let store = store_from_url_with_credentials(
            &url,
            [("region", "us-east-1")],
            fixed(StorageCredential::Aws {
                key_id: "AKIAEXAMPLE".into(),
                secret: "s3-secret".into(),
                session_token: Some("s3-session".into()),
            }),
        )
        .expect("build store");

        assert!(store.to_string().contains("AmazonS3"), "{store}");
    }

    #[test]
    fn azure_url_builds_a_microsoft_store_from_a_sas_token() {
        let url = Url::parse("abfss://container@account.dfs.core.windows.net/some-table")
            .expect("parse url");
        let store = store_from_url_with_credentials(
            &url,
            std::iter::empty::<(&str, &str)>(),
            fixed(StorageCredential::AzureSas(
                "sv=2021-01-01&sig=example".into(),
            )),
        )
        .expect("build store");

        assert!(store.to_string().contains("MicrosoftAzure"), "{store}");
    }

    #[test]
    fn a_credential_from_another_cloud_is_rejected_at_construction() {
        let url = Url::parse("gs://some-bucket/some-table").expect("parse url");
        let err = store_from_url_with_credentials(
            &url,
            std::iter::empty::<(&str, &str)>(),
            fixed(StorageCredential::AzureSas(
                "sv=2021-01-01&sig=example".into(),
            )),
        )
        .expect_err("Azure credential must not build a GCS store");

        let message = err.to_string();
        assert!(message.contains("Azure"), "{message}");
        assert!(message.contains("gs"), "{message}");
    }

    /// Example funciton of doing testing of a custom [HdfsObjectStore] construction
    fn parse_url_opts_hdfs_native<I, K, V>(
        url: &Url,
        options: I,
    ) -> Result<(Box<dyn ObjectStore>, Path), object_store::Error>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: Into<String>,
    {
        let options_map = options
            .into_iter()
            .map(|(k, v)| (k.as_ref().to_string(), v.into()));
        let store = HdfsObjectStoreBuilder::new()
            .with_url(url.as_str())
            .with_config(options_map)
            .build()?;
        let path = Path::parse(url.path())?;
        Ok((Box::new(store), path))
    }

    #[test]
    fn test_add_hdfs_scheme() {
        let scheme = "hdfs";
        if let Ok(handlers) = URL_REGISTRY.read() {
            assert!(handlers.get(scheme).is_none());
        } else {
            panic!("Failed to read the RwLock for the registry");
        }
        insert_url_handler(scheme, Arc::new(parse_url_opts_hdfs_native))
            .expect("Failed to add new URL scheme handler");

        if let Ok(handlers) = URL_REGISTRY.read() {
            assert!(handlers.get(scheme).is_some());
        } else {
            panic!("Failed to read the RwLock for the registry");
        }

        let url: Url = Url::parse("hdfs://example").expect("Failed to parse URL");
        let options: HashMap<String, String> = HashMap::default();
        // Currently constructing an [HdfsObjectStore] won't work if there isn't an actual HDFS
        // to connect to, so the only way to really verify that we got the object store we
        // expected is to inspect the `store` on the error v_v
        match store_from_url_opts(&url, options) {
            Err(delta_kernel::Error::ObjectStore(object_store::Error::Generic {
                store,
                source: _,
            })) => {
                assert_eq!(store, "HdfsObjectStore");
            }
            Err(unexpected) => panic!("Unexpected error happened: {unexpected:?}"),
            Ok(_) => {
                panic!("Expected to get an error when constructing an HdfsObjectStore, but something didn't work as expected! Either the parse_url_opts_hdfs_native function didn't get called, or the hdfs-native-object-store no longer errors when it cannot connect to HDFS");
            }
        }
    }
}
