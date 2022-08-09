use axum::{response::Response, Extension, extract::Query};
use oxide_auth::{
    endpoint::{OwnerConsent, Solicitation},
    frontends::simple::endpoint::FnSolicitor,
};
use oxide_auth_axum::{OAuthRequest, OAuthResponse, WebError};
use serde::Deserialize;
use std::sync::Arc;

use super::OauthState;

pub async fn handle(
    oauth: OAuthRequest,
    Extension(state): Extension<Arc<OauthState>>,
) -> Result<OAuthResponse<String>, WebError> {
    state
        .endpoint()
        .with_solicitor(FnSolicitor(consent_form))
        .authorization_flow()
        .execute(oauth)
        .map_err(|err| err.pack::<WebError>())
}

fn consent_form(_: &mut OAuthRequest, solicitation: Solicitation) -> OwnerConsent<OAuthResponse<String>> {
    Response::builder()
        .header("Content-Type", "text/html")
        .body(consent_page_html("/oauth/authorize", solicitation))
        .map_err(|_| WebError::EncodeResponse)
        .map_err(OwnerConsent::Error)
        .map(OAuthResponse::from)
        .map(OwnerConsent::InProgress)
        .into_ok_or_err()
}

fn consent_page_html(route: &str, solicitation: Solicitation) -> String {
    let grant = solicitation.pre_grant();
    let state = solicitation.state();

    let mut extra = vec![
        ("response_type", "code"),
        ("client_id", grant.client_id.as_str()),
        ("redirect_uri", grant.redirect_uri.as_str()),
    ];

    if let Some(state) = state {
        extra.push(("state", state));
    }

    format!(
        "<html>'{0:}' (at {1:}) is requesting permission for '{2:}'
<form method=\"post\">
    <input type=\"submit\" value=\"Accept\" formaction=\"{4:}?{3:}&allow=true\">
    <input type=\"submit\" value=\"Deny\" formaction=\"{4:}?{3:}&deny=true\">
</form>
</html>",
        grant.client_id,
        grant.redirect_uri,
        grant.scope,
        serde_urlencoded::to_string(extra).unwrap(),
        &route,
    )
}

#[derive(Deserialize)]
pub struct AuthorizeQuery {
    allow: bool,
}

pub async fn handle_consent(
    oauth: OAuthRequest, query: Query<AuthorizeQuery>, Extension(state): Extension<Arc<OauthState>>,
) -> Result<OAuthResponse<String>, WebError> {
    state
        .endpoint()
        .with_solicitor(FnSolicitor(move |_: &mut _, grant: Solicitation<'_>| {
            consent_decision(query.allow, grant)
        }))
        .authorization_flow()
        .execute(oauth)
        .map_err(|err| err.pack::<WebError>())
}

fn consent_decision<'r>(allowed: bool, _: Solicitation) -> OwnerConsent<OAuthResponse<String>> {
    if allowed {
        OwnerConsent::Authorized("dummy user".into())
    } else {
        OwnerConsent::Denied
    }
}