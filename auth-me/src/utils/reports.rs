
use std::sync::Arc;

use axum::{
    extract::State,
    response::Json,
};
use serde_json::{json, Value};

use crate::{
    AppState,
    errors::HttpError,
};

pub async fn get_reports(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<Value>, HttpError> {
    // just for testing, will fetch reports from database
    // This is just a placeholder implementation
    let reports = json!({
        "reports": [
            {
                "id": 1,
                "title": "Monthly Sales Report",
                "created_at": "2024-01-15T10:30:00Z",
                "type": "sales"
            },
            {
                "id": 2,
                "title": "User Activity Report",
                "created_at": "2024-01-14T09:15:00Z",
                "type": "analytics"
            }
        ],
        "total_count": 2
    });

    Ok(Json(reports))
}