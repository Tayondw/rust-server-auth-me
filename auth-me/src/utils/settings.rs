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

pub async fn admin_settings(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<Value>, HttpError> {
    // Admin system settings
    let settings = json!({
        "system_settings": {
            "maintenance_mode": false,
            "registration_enabled": true,
            "email_verification_required": true,
            "password_min_length": 8,
            "session_timeout_minutes": 60,
            "max_login_attempts": 5
        },
        "statistics": {
            "total_users": 150,
            "active_sessions": 25,
            "failed_login_attempts_today": 3,
            "system_uptime": "15 days, 4 hours"
        }
    });

    Ok(Json(settings))
}