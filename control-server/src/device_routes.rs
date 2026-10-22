// SPDX-License-Identifier: BSD-3-Clause
//! Device-owned pending route requests. Approval remains administrator-only.
use super::*;

impl SqlStore {
    pub async fn device_route_change(&self, device: &str, token: &str, prefix: &str, withdraw: bool) -> Result<Vec<Route>> {
        crate::contention::retry("device_route_change", false, || self.device_route_change_once(device, token, prefix, withdraw)).await
    }

    async fn device_route_change_once(&self, device: &str, token: &str, prefix: &str, withdraw: bool) -> Result<Vec<Route>> {
        let mut tx = crate::integrity::begin(&self.pool).await?;
        let stored: Option<String> = sqlx::query_scalar("SELECT auth_token FROM device WHERE id = $1 AND status = 'active' AND auth_token IS NOT NULL AND EXISTS (SELECT 1 FROM network WHERE network.id = device.network_id)")
            .bind(device).fetch_optional(&mut *tx).await?;
        if token.is_empty() || !stored.is_some_and(|v| crate::ct_eq(v.as_bytes(), token.as_bytes())) {
            let known: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device WHERE auth_token = $1 AND status = 'active' AND EXISTS (SELECT 1 FROM network WHERE network.id = device.network_id)")
                .bind(token).fetch_one(&mut *tx).await?;
            return Err(if !token.is_empty() && known > 0 { SqlStoreError::DeviceForbidden } else { SqlStoreError::DeviceUnauthorized });
        }
        let prefix = normalize_prefix(prefix).ok_or(SqlStoreError::InvalidPrefix)?;
        // Lock matching rows too: administrator approval must not race pending-only withdrawal.
        sqlx::query("UPDATE route SET approved = approved WHERE device_id = $1 AND prefix = $2")
            .bind(device).bind(&prefix).execute(&mut *tx).await?;
        let routes = db::list_routes_for_device(&mut *tx, device).await?;
        if withdraw {
            if routes.iter().any(|r| r.prefix == prefix && r.approved) { return Err(SqlStoreError::RouteApproved); }
            sqlx::query("DELETE FROM route WHERE device_id = $1 AND prefix = $2 AND approved = 0")
                .bind(device).bind(&prefix).execute(&mut *tx).await?;
        } else if !routes.iter().any(|r| r.prefix == prefix) {
            let dev = db::get_device(&mut *tx, device).await?.ok_or(SqlStoreError::DeviceNotFound)?;
            let route = Route { id: format!("route-{}", crate::integrity::next(&mut tx).await?),
                network_id: dev.network_id, device_id: device.to_string(), prefix, approved: false };
            db::insert_route(&mut *tx, &route).await?;
        }
        let mut routes = db::list_routes_for_device(&mut *tx, device).await?;
        routes.sort_by(|a, b| (&a.prefix, &a.id).cmp(&(&b.prefix, &b.id)));
        tx.commit().await?;
        Ok(routes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::{Request, StatusCode}};
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    async fn call(app: &axum::Router, method: &str, path: &str, token: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let response = app.clone().oneshot(Request::builder().method(method).uri(format!("/api/v1{path}"))
            .header("authorization", format!("Bearer {token}")).header("content-type", "application/json")
            .body(Body::from(body.to_string())).unwrap()).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    #[tokio::test]
    async fn device_routes_http_own_token_only_pending_and_actual_approval_state() {
        use serde_json::json;
        let s = Arc::new(SqlStore::connect("sqlite::memory:").await.unwrap());
        let net = s.create_network("routes").await.unwrap();
        let invite = s.create_invite(&net.id, None, None).await.unwrap();
        let (me, token) = s.enroll(&invite.code, "router", &hex::encode([61;32]), 0).await.unwrap();
        let (other, other_token) = s.enroll(&invite.code, "other", &hex::encode([62;32]), 0).await.unwrap();
        let app = crate::sql_router(s.clone());
        let path = format!("/devices/{}/route-advertisements", me.id);
        for method in ["POST", "DELETE"] {
            for (credential, expected) in [("", StatusCode::UNAUTHORIZED), ("wrong", StatusCode::UNAUTHORIZED), (other_token.as_str(), StatusCode::FORBIDDEN)] {
                assert_eq!(call(&app, method, &path, credential, json!({"prefix":"192.168.8.1/24"})).await.0, expected);
            }
        }
        assert!(s.list_device_routes(&me.id).await.unwrap().is_empty());
        assert_eq!(call(&app, "POST", &path, &token, json!({"prefix":"invalid"})).await.0, StatusCode::BAD_REQUEST);
        let (status, rows) = call(&app, "POST", &path, &token, json!({"prefix":"192.168.8.1/24","approved":true,"device_id":other.id})).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(rows[0]["device_id"], me.id); assert_eq!(rows[0]["prefix"], "192.168.8.0/24"); assert_eq!(rows[0]["approved"], false);
        let (_, repeated) = call(&app, "POST", &path, &token, json!({"prefix":"192.168.8.7/24"})).await;
        assert_eq!(repeated, rows);
        let id = rows[0]["id"].as_str().unwrap();
        assert_eq!(call(&app, "POST", &format!("/routes/{id}/approve"), &token, json!({})).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(call(&app, "POST", &format!("/devices/{}/routes", me.id), &token, json!({"prefix":"10.0.0.0/8"})).await.0, StatusCode::UNAUTHORIZED);
        s.approve_route(id).await.unwrap();
        let (_, read) = call(&app, "GET", &format!("/devices/{}/routes", me.id), &token, json!(null)).await;
        assert_eq!(read[0]["approved"], true);
        assert_eq!(call(&app, "GET", &format!("/devices/{}/routes", me.id), &other_token, json!(null)).await.0, StatusCode::FORBIDDEN);
        assert_eq!(call(&app, "DELETE", &path, &token, json!({"prefix":"192.168.8.0/24"})).await.0, StatusCode::CONFLICT);
        let (_, readvertised) = call(&app, "POST", &path, &token, json!({"prefix":"192.168.8.2/24"})).await;
        assert_eq!(readvertised[0]["approved"], true);
        let before = s.device_config(&me.id).await.unwrap().config_epoch;
        assert_eq!(call(&app, "POST", &path, &token, json!({"prefix":"10.9.8.7/16"})).await.1.as_array().unwrap().len(), 2);
        for _ in 0..2 {
            let (status, remaining) = call(&app, "DELETE", &path, &token, json!({"prefix":"10.9.0.0/16"})).await;
            assert_eq!(status, StatusCode::OK); assert_eq!(remaining.as_array().unwrap().len(), 1);
        }
        assert_eq!(s.device_config(&me.id).await.unwrap().config_epoch, before);
        assert!(s.list_device_routes(&other.id).await.unwrap().is_empty());
        s.revoke_device(&me.id).await.unwrap();
        for method in ["POST", "DELETE"] {
            assert_eq!(call(&app, method, &path, &token, json!({"prefix":"10.0.0.0/8"})).await.0, StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn device_routes_rollback_and_cross_store_duplicate_requests() {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}?mode=rwc", dir.path().join("routes.db").display());
        let s = SqlStore::connect(&url).await.unwrap();
        let second = SqlStore::connect(&url).await.unwrap();
        let net = s.create_network("race").await.unwrap();
        let invite = s.create_invite(&net.id, None, None).await.unwrap();
        let (dev, token) = s.enroll(&invite.code, "router", &hex::encode([63;32]), 0).await.unwrap();
        let (a, b) = tokio::join!(s.device_route_change(&dev.id, &token, "10.1.1.1/16", false), second.device_route_change(&dev.id, &token, "10.1.2.2/16", false));
        let a = a.unwrap(); let b = b.unwrap();
        assert_eq!(a.len(), 1); assert_eq!(b.len(), 1); assert_eq!(a[0].id, b[0].id);
        sqlx::query("CREATE TRIGGER fail_route_delete BEFORE DELETE ON route BEGIN SELECT RAISE(ABORT, 'injected route delete failure'); END")
            .execute(&s.pool).await.unwrap();
        assert!(s.device_route_change(&dev.id, &token, "10.1.0.0/16", true).await.is_err());
        assert_eq!(s.list_device_routes(&dev.id).await.unwrap().len(), 1);
        sqlx::query("DROP TRIGGER fail_route_delete").execute(&s.pool).await.unwrap();
        let (withdraw, approve) = tokio::join!(s.device_route_change(&dev.id, &token, "10.1.0.0/16", true), second.approve_route(&a[0].id));
        let remaining = s.list_device_routes(&dev.id).await.unwrap();
        match withdraw {
            Ok(routes) => { assert!(routes.is_empty()); assert!(remaining.is_empty()); }
            Err(SqlStoreError::RouteApproved) => { approve.unwrap(); assert!(remaining[0].approved); }
            Err(error) => panic!("unexpected withdrawal error: {error}"),
        }
    }
}
