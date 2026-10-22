// SPDX-License-Identifier: BSD-3-Clause
use super::*;
use axum::{body::Body, extract::{Json, WebSocketUpgrade, ws::Message}, http::Request, routing::{get, post}};
use futures_util::{SinkExt, StreamExt};
use http_body_util::BodyExt;
use std::{io::{Read, Seek}, sync::{Arc, atomic::{AtomicBool, Ordering}}};

#[test]
fn timeout_configuration_is_bounded_and_has_a_safe_default() {
    assert_eq!(parse_timeout(None), Duration::from_secs(30));
    assert_eq!(parse_timeout(Some("12")), Duration::from_secs(12));
    assert_eq!(parse_timeout(Some("3600")), Duration::from_secs(3600));
    for invalid in ["", "0", "-1", "1.5", "3601", "18446744073709551615"] {
        assert_eq!(parse_timeout(Some(invalid)), DEFAULT_TIMEOUT);
    }
}

#[tokio::test]
async fn deadline_covers_body_and_handler_and_logs_only_safe_metadata() {
    let capture = tempfile::tempfile().unwrap();
    let mut reader = capture.try_clone().unwrap();
    let subscriber = tracing_subscriber::fmt().without_time().with_ansi(false)
        .with_max_level(tracing::Level::ERROR).with_writer(move || capture.try_clone().unwrap()).finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let app = apply(Router::new()
        .route("/invites/:code", post(|| async { std::future::pending::<StatusCode>().await }))
        .route("/body", post(|Json(_): Json<serde_json::Value>| async { StatusCode::OK })), Duration::from_millis(30));
    for (path, body) in [
        ("/invites/secret-code?token=secret-query", Body::empty()),
        ("/body", Body::from_stream(futures_util::stream::pending::<Result<String, std::io::Error>>())),
    ] {
        let response = tokio::time::timeout(Duration::from_secs(1), app.clone().oneshot(Request::builder()
            .method("POST").uri(path).header("authorization", "Bearer secret-header")
            .header("content-type", "application/json").body(body).unwrap())).await.unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(response.into_body().collect().await.unwrap().to_bytes().is_empty());
    }
    reader.rewind().unwrap();
    let mut output = String::new(); reader.read_to_string(&mut output).unwrap();
    assert_eq!(output.matches("ERROR").count(), 2, "{output}");
    for field in ["method=POST", "route=/invites/:code", "route=/body", "elapsed_ms=", "deadline exceeded"] {
        assert!(output.contains(field), "{output}");
    }
    assert!(!output.contains("secret-"), "{output}");
}

#[tokio::test]
async fn cancelled_handler_rolls_back_and_returns_its_connection() {
    let pool = crate::persistence::connect("sqlite::memory:").await.unwrap();
    sqlx::query("CREATE TABLE cancellation (value BIGINT)").execute(&pool).await.unwrap();
    let entered = Arc::new(AtomicBool::new(false));
    let handler_pool = pool.clone();
    let handler_entered = entered.clone();
    let app = apply(Router::new().route("/write", post(move || {
        let pool = handler_pool.clone(); let entered = handler_entered.clone();
        async move {
            let mut tx = pool.begin().await.unwrap();
            sqlx::query("INSERT INTO cancellation VALUES (1)").execute(&mut *tx).await.unwrap();
            entered.store(true, Ordering::SeqCst);
            std::future::pending::<()>().await;
            tx.commit().await.unwrap();
            StatusCode::OK
        }
    })), Duration::from_millis(100));
    let response = app.oneshot(Request::post("/write").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(entered.load(Ordering::SeqCst), "must cancel after the transaction has written");
    let (count,): (i64,) = tokio::time::timeout(Duration::from_secs(1),
        sqlx::query_as("SELECT COUNT(*) FROM cancellation").fetch_one(&pool)).await.unwrap().unwrap();
    assert_eq!(count, 0, "cancelled transaction must roll back before connection reuse");
    pool.close().await;
}

#[tokio::test]
async fn upgraded_websocket_outlives_the_http_deadline() {
    let app = apply(Router::new().route("/watch", get(|ws: WebSocketUpgrade| async {
        ws.on_upgrade(|mut socket| async move {
            while let Some(Ok(message)) = socket.recv().await {
                if let Message::Text(text) = message
                    && socket.send(Message::Text(text)).await.is_err() {
                    break;
                }
            }
        })
    })), Duration::from_millis(50));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
    let (mut socket, response) = tokio_tungstenite::connect_async(format!("ws://{address}/watch")).await.unwrap();
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    tokio::time::sleep(Duration::from_millis(150)).await;
    socket.send(tokio_tungstenite::tungstenite::Message::Text("still alive".into())).await.unwrap();
    let echoed = tokio::time::timeout(Duration::from_secs(1), socket.next()).await.unwrap().unwrap().unwrap();
    assert_eq!(echoed.to_text().unwrap(), "still alive");
    socket.close(None).await.unwrap();
    server.abort(); let _ = server.await;
}
