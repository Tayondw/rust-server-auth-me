use std::io::Write;

use diesel::{
    prelude::*,
    pg::{ Pg, PgValue },
    serialize::{ self, Output, ToSql, IsNull },
    deserialize::{ self, FromSql },
    sql_types::SqlType,
    AsExpression,
    FromSqlRow,
};
use serde::{ Deserialize, Serialize };
use chrono::{ DateTime, Utc };
use uuid::Uuid;

use crate::schema::users;

#[derive(SqlType)]
#[diesel(postgres_type(name = "user_role"))]
pub struct UserRoleType;

#[derive(Debug, Deserialize, Serialize, Clone, Copy, AsExpression, PartialEq, FromSqlRow)]
#[diesel(sql_type = UserRoleType)]
pub enum UserRole {
    Admin,
    User,
}

impl UserRole {
    pub fn to_str(&self) -> &'static str {
        match self {
            UserRole::Admin => "admin",
            UserRole::User => "user",
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
}

#[derive(AsChangeset, Deserialize, Debug)]
#[diesel(table_name = users)]
pub struct UpdateUser {
    pub name: Option<String>,
    pub username: Option<String>,
    pub email: Option<String>,
    pub password: Option<String>,
}
