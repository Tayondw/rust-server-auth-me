use diesel::prelude::*;
use serde::{ Deserialize, Serialize };
use crate::schema::users;
use chrono;

#[derive(Queryable, Serialize, Debug, Selectable, Identifiable)]
#[diesel(table_name = users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: i32,
    pub name: String,
    pub username: String,
    pub email: String,
    pub password: String,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub is_verified: bool,
    pub verification_token: Option<String>,
}

#[derive(Insertable, Deserialize, Debug)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub name: String,
    pub username: String,
    pub email: String,
    pub password: String,
    pub is_verified: bool,
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
