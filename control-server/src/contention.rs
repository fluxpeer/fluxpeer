// SPDX-License-Identifier: BSD-3-Clause
//! Retry SQLite write transactions only after the previous future has dropped.

use std::{future::Future, time::Duration};
use crate::sql_store::SqlStoreError;

pub(crate) fn sqlite_busy(error: &sqlx::Error) -> bool {
    use sqlx::error::DatabaseError;
    error.as_database_error()
        .and_then(|error| error.try_downcast_ref::<sqlx::sqlite::SqliteError>())
        .and_then(|error| error.code())
        .and_then(|code| code.parse::<u32>().ok())
        // Extended codes (BUSY_SNAPSHOT, LOCKED_SHAREDCACHE, etc.) retain
        // the primary error in the low byte. Never classify PostgreSQL by text.
        .is_some_and(|code| matches!(code & 0xff, 5 | 6))
}

pub(crate) async fn retry<T, F, Fut>(operation: &'static str, legacy_pg_retry: bool, mut write: F) -> Result<T, SqlStoreError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, SqlStoreError>>,
{
    let mut attempt = 0;
    loop {
        match write().await {
            Err(SqlStoreError::Db(error)) if sqlite_busy(&error) => {
                // Three total attempts; no nested statement/transaction retries.
                if attempt >= 2 {
                    tracing::warn!(operation, attempts = attempt + 1, "SQLite write contention exhausted retries");
                    return Err(SqlStoreError::Db(error));
                }
                let delay_ms = (50_u64 << attempt) + rand::random_range(0..=50);
                tracing::warn!(operation, attempt = attempt + 1, delay_ms, "SQLite write busy; retrying transaction");
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                attempt += 1;
            }
            Err(SqlStoreError::Db(error)) if legacy_pg_retry && crate::integrity::retryable(&error) && attempt < 7 => {
                // Preserve the existing PostgreSQL serialization/deadlock policy.
                tokio::time::sleep(Duration::from_millis(10 << attempt)).await;
                attempt += 1;
            }
            result => return result,
        }
    }
}
