#![feature(result_into_ok_or_err)]

use axum::{Router, Server};
use clap::Parser;
use hyper::{Error, header::AUTHORIZATION};
use std::{net::SocketAddr, iter::once};
use tower_http::{compression::CompressionLayer, trace::TraceLayer, sensitive_headers::SetSensitiveRequestHeadersLayer};
use tracing::{info, metadata::LevelFilter};
use tracing_subscriber::prelude::*;

mod oauth;

/// A web service that provides user authentication
/// and third party access using OAuth2.
#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    /// Socket address to bind to.
    #[clap(short, long, value_parser, default_value = "127.0.0.1:8000")]
    addr: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let stdout = tracing_subscriber::fmt::layer()
        .pretty()
        .with_filter(LevelFilter::DEBUG);
    tracing_subscriber::registry()
        .with(stdout)
        .init();

    let args = Args::parse();
    info!("listening on http://{}", args.addr);

    let app = Router::new()
        .nest("/oauth", oauth::router())
        .layer(SetSensitiveRequestHeadersLayer::new(once(AUTHORIZATION)))
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http());

    Server::bind(&args.addr)
        .serve(app.into_make_service())
        .await
}
