// SPDX-License-Identifier: BSD-3-Clause
//! Bound the full HTTP handler future, including authentication and body reads.

use std::time::{Duration, Instant};
use axum::{Router, extract::{MatchedPath, Request, State}, http::StatusCode,
    middleware::{Next, from_fn_with_state}, response::{IntoResponse, Response}};
use tower::{ServiceExt, timeout::Timeout};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

fn parse_timeout(value: Option<&str>) -> Duration {
    match value {
        None => DEFAULT_TIMEOUT,
        Some(value) => match value.parse::<u64>() {
            Ok(seconds @ 1..=3600) => Duration::from_secs(seconds),
            _ => {
                tracing::warn!("invalid FLUXPEER_CONTROL_HTTP_TIMEOUT_SECS; using 30 seconds (valid range: 1..=3600)");
                DEFAULT_TIMEOUT
            }
        },
    }
}

pub(crate) fn configured_timeout() -> Duration {
    parse_timeout(std::env::var("FLUXPEER_CONTROL_HTTP_TIMEOUT_SECS").ok().as_deref())
}

pub(crate) fn apply(router: Router, timeout: Duration) -> Router {
    router.layer(from_fn_with_state(timeout, deadline))
}

async fn deadline(State(timeout): State<Duration>, request: Request, next: Next) -> Response {
    let method = request.method().clone();
    // Use the route template: concrete paths can contain invite codes, and the
    // query or Authorization header may contain bearer credentials.
    let route = request.extensions().get::<MatchedPath>().map(|path| path.as_str().to_owned())
        .unwrap_or_else(|| "<unmatched>".into());
    let started = Instant::now();
    // An upgraded WebSocket is driven by its own task after the 101 response;
    // only the upgrade/authentication handler is covered by this deadline.
    let result = Timeout::new(next, timeout).oneshot(request).await;
    let elapsed_ms = started.elapsed().as_millis() as u64;
    let mut response = match result {
        Ok(response) => {
            let status = response.status().as_u16();
            if started.elapsed() > Duration::from_secs(1) {
                tracing::warn!(%method, %route, status, elapsed_ms, "slow control request");
            } else {
                tracing::debug!(%method, %route, status, elapsed_ms, "control request completed");
            }
            response
        }
        Err(_) => {
            tracing::error!(%method, %route, elapsed_ms, "control HTTP deadline exceeded");
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    };
    if response.status() == StatusCode::SERVICE_UNAVAILABLE {
        response.headers_mut().entry(axum::http::header::RETRY_AFTER)
            .or_insert(axum::http::HeaderValue::from_static("1"));
    }
    response
}

#[cfg(test)]
#[path = "http_limits_tests.rs"]
mod tests;
