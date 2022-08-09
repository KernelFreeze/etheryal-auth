use std::sync::{Arc, Mutex};

use axum::{
    routing::{get, post},
    Extension, Router,
};
use oxide_auth::{
    endpoint::{Authorizer, Issuer, Registrar},
    frontends::simple::endpoint::{Generic, Vacant},
    primitives::{
        prelude::{AuthMap, RandomGenerator, TokenMap},
        registrar::{Client, ClientMap, RegisteredUrl},
    },
};

mod authorize;
mod token;
mod refresh;

pub struct OauthState {
    registrar: Mutex<ClientMap>,
    authorizer: Mutex<AuthMap<RandomGenerator>>,
    issuer: Mutex<TokenMap<RandomGenerator>>,
}

impl OauthState {
    pub fn preconfigured() -> Self {
        OauthState {
            registrar: Mutex::new(
                vec![Client::public(
                    "LocalClient",
                    RegisteredUrl::Semantic(
                        "http://localhost:8000/clientside/endpoint".parse().unwrap(),
                    ),
                    "default-scope".parse().unwrap(),
                )]
                .into_iter()
                .collect(),
            ),

            // Authorization tokens are 16 byte random keys to a memory hash map.
            authorizer: Mutex::new(AuthMap::new(RandomGenerator::new(16))),

            // Bearer tokens are also random generated but 256-bit tokens, since they live longer
            // and this example is somewhat paranoid.
            //
            // We could also use a `TokenSigner::ephemeral` here to create signed tokens which can
            // be read and parsed by anyone, but not maliciously created. However, they can not be
            // revoked and thus don't offer even longer lived refresh tokens.
            issuer: Mutex::new(TokenMap::new(RandomGenerator::new(16))),
        }
    }

    pub fn endpoint(&self) -> Generic<impl Registrar + '_, impl Authorizer + '_, impl Issuer + '_> {
        Generic {
            registrar: self.registrar.lock().unwrap(),
            authorizer: self.authorizer.lock().unwrap(),
            issuer: self.issuer.lock().unwrap(),
            solicitor: Vacant,
            scopes: Vacant,
            response: Vacant,
        }
    }
}

pub fn router() -> Router {
    Router::new()
        .route("/authorize", get(authorize::handle))
        .route("/authorize", post(authorize::handle_consent))
        .route("/token", post(token::handle))
        .route("/refresh", post(refresh::handle))
        .layer(Extension(Arc::new(OauthState::preconfigured())))
}
