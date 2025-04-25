use std::sync::Arc;
use diesel::{ r2d2::{ ConnectionManager, PooledConnection }, PgConnection };

use crate::{ AppState, errors::{ HttpError, ErrorMessage } };

pub trait DbConnExt {
    fn conn(&self) -> Result<PooledConnection<ConnectionManager<PgConnection>>, HttpError>;
}

impl DbConnExt for Arc<AppState> {
    fn conn(&self) -> Result<PooledConnection<ConnectionManager<PgConnection>>, HttpError> {
        self.db_pool
            .get()
            .map_err(|_| { HttpError::server_error(ErrorMessage::DatabaseError.to_string()) })
    }
}
