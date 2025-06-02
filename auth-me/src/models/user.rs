use std::io::Write;

use diesel::{
    prelude::*,
    pg::{ Pg, PgValue },
    serialize::{ self, Output, ToSql, IsNull },
    deserialize::{ self, FromSql },
    AsExpression,
    FromSqlRow,
    query_builder::QueryId,
};
use serde::{ Deserialize, Serialize };
use chrono::{ DateTime, Utc };
use uuid::Uuid;

use crate::schema::{ users, sql_types::UserRole as UserRoleType };

// Implement QueryId for UserRoleType
impl QueryId for UserRoleType {
    type QueryId = UserRoleType;
    const HAS_STATIC_QUERY_ID: bool = true;
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, AsExpression, PartialEq, FromSqlRow, Eq)]
#[diesel(sql_type = UserRoleType)]
pub enum UserRole {
    Admin,
    User,
    Manager,
    Moderator,
}

impl UserRole {
    pub fn to_str(&self) -> &'static str {
        match self {
            UserRole::Admin => "admin",
            UserRole::User => "user",
            UserRole::Manager => "manager",
            UserRole::Moderator => "moderator",
        }
    }
}

// Serialize enum to SQL
impl ToSql<UserRoleType, Pg> for UserRole {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
        out.write_all(self.to_str().as_bytes())?;
        Ok(IsNull::No)
    }
}

// Deserialize enum from SQL
impl FromSql<UserRoleType, Pg> for UserRole {
    fn from_sql(value: PgValue<'_>) -> deserialize::Result<Self> {
        match value.as_bytes() {
            b"admin" => Ok(UserRole::Admin),
            b"user" => Ok(UserRole::User),
            b"manager" => Ok(UserRole::Manager),
            b"moderator" => Ok(UserRole::Moderator),
            _ => Err("Unrecognized enum variant for user_role".into()),
        }
    }
}

#[derive(Queryable, Serialize, Deserialize, Debug, Selectable, Identifiable, Clone)]
#[diesel(table_name = users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: Uuid,
    pub name: String,
    pub email: String,
    pub username: String,
    pub password: String,
    pub verified: bool,
    pub verification_token: Option<String>,
    pub token_expires_at: Option<DateTime<Utc>>,
    pub role: UserRole,
    pub created_by: Option<Uuid>,
    pub force_password_change: bool,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Insertable, Deserialize, Debug)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub name: String,
    pub email: String,
    pub username: String,
    pub password: String,
    pub verified: bool,
    pub verification_token: Option<String>,
    pub token_expires_at: Option<DateTime<Utc>>,
    pub role: UserRole,
    pub created_by: Option<Uuid>,
    pub force_password_change: bool,
}

#[derive(AsChangeset, Deserialize, Debug)]
#[diesel(table_name = users)]
pub struct UpdateUser {
    pub name: String,
    pub email: String,
    pub username: String,
    pub password: String,
    pub verified: bool,
    pub role: UserRole,
    pub updated_at: DateTime<Utc>,
}
