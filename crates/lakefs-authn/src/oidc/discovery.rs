//! One discovery round: provider metadata, JWKS, and the optional logout endpoint.

use openidconnect::core::CoreProviderMetadata;
use openidconnect::{
    ClientId, ClientSecret, DiscoveryError, EndSessionUrl, IssuerUrl, ProviderMetadataWithLogout, RedirectUrl,
};

use crate::oidc::types::AuthnClient;

/// Everything one successful discovery produced.
pub struct Discovered {
    pub client: AuthnClient,
    /// Present only when RP-initiated logout is on and the provider advertises it.
    pub end_session_endpoint: Option<EndSessionUrl>,
}

impl std::fmt::Debug for Discovered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Discovered")
            .field(
                "end_session_endpoint",
                &self.end_session_endpoint.as_ref().map(|e| e.as_str()),
            )
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("OpenID Connect discovery failed: {0}")]
pub struct DiscoveryFailure(String);

pub(crate) struct DiscoveryRequest<'a> {
    pub http: &'a reqwest::Client,
    pub issuer: &'a IssuerUrl,
    pub client_id: &'a ClientId,
    pub client_secret: Option<&'a ClientSecret>,
    pub redirect_uri: &'a RedirectUrl,
    pub want_logout_metadata: bool,
}

/// Fetches the discovery document and the JWKS once.
///
/// The document is read in the shape that carries `end_session_endpoint`, so
/// the logout data costs no second round. A document whose logout data does
/// not parse is read again without it: a provider with odd logout metadata
/// still serves logins, and only that rare case pays a second fetch.
pub(crate) async fn discover(request: DiscoveryRequest<'_>) -> Result<Discovered, DiscoveryFailure> {
    let issuer = request.issuer.clone();
    let (client, end_session_endpoint) = match ProviderMetadataWithLogout::discover_async(issuer.clone(), request.http)
        .await
    {
        Ok(metadata) => {
            let end_session_endpoint = metadata.additional_metadata().end_session_endpoint.clone();
            let client = AuthnClient::from_provider_metadata(
                metadata,
                request.client_id.clone(),
                request.client_secret.cloned(),
            );
            (client, end_session_endpoint)
        }
        Err(DiscoveryError::Parse(error)) => {
            tracing::warn!(error = %error, "provider metadata did not parse with its logout data; reading it without");
            let metadata = CoreProviderMetadata::discover_async(issuer, request.http)
                .await
                .map_err(|error| DiscoveryFailure(format!("{error}")))?;
            let client = AuthnClient::from_provider_metadata(
                metadata,
                request.client_id.clone(),
                request.client_secret.cloned(),
            );
            (client, None)
        }
        Err(error) => return Err(DiscoveryFailure(format!("{error}"))),
    };

    Ok(Discovered {
        client: client.set_redirect_uri(request.redirect_uri.clone()),
        end_session_endpoint: end_session_endpoint.filter(|_| request.want_logout_metadata),
    })
}
