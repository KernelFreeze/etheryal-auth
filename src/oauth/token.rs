use axum::Extension;
use oxide_auth_axum::{OAuthRequest, OAuthResponse, WebError};
use std::sync::Arc;

use super::OauthState;

pub async fn handle(
    oauth: OAuthRequest,
    Extension(state): Extension<Arc<OauthState>>,
) -> Result<OAuthResponse<String>, WebError> {
    state
        .endpoint()
        .access_token_flow()
        .execute(oauth)
        .map_err(|err| err.pack::<WebError>())
}
