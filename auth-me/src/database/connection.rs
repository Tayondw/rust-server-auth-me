use std::sync::Arc;
use axum::{ http::StatusCode, Json };
use diesel::{r2d2::{ ConnectionManager, PooledConnection }, PgConnection};

use crate::{ AppState, ErrorResponse };

pub trait DbConnExt {
    fn conn(
        &self
    ) -> Result<
        PooledConnection<ConnectionManager<PgConnection>>,
        (StatusCode, Json<ErrorResponse>)
    >;
}

impl DbConnExt for Arc<AppState> {
    fn conn(
        &self
    ) -> Result<
        PooledConnection<ConnectionManager<PgConnection>>,
        (StatusCode, Json<ErrorResponse>)
    > {
        self.db_pool.get().map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    message: format!("Database connection error: {}", e),
                }),
            )
        })
    }
}
