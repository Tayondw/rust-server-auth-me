use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::{ Deserialize, Serialize };
use uuid::Uuid;

use crate::{ schema::pending_users, models::UserRole };

#[derive(Queryable, Serialize, Deserialize, Debug, Selectable, Identifiable, Clone)]
#[diesel(table_name = pending_users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct PendingUser {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub username: String,
    pub password: String,
    pub verification_token: String,
    pub token_expires_at: NaiveDateTime,
    pub role: UserRole,
    pub created_by: Option<Uuid>,
    pub send_welcome_email: bool,
    pub temp_password: Option<String>, // Store unhashed for welcome email
    pub has_temp_password: bool,
    pub force_password_change: bool,
    pub created_at: Option<NaiveDateTime>,
}

#[derive(Insertable, Deserialize, Debug)]
#[diesel(table_name = pending_users)]
pub struct NewPendingUser {
    pub name: String,
    pub email: String,
    pub username: String,
    pub password: String,
    pub verification_token: String,
    pub token_expires_at: NaiveDateTime,
    pub role: UserRole,
    pub created_by: Option<Uuid>,
    pub send_welcome_email: bool,
    pub temp_password: Option<String>,
    pub has_temp_password: bool,
    pub force_password_change: bool,
}
