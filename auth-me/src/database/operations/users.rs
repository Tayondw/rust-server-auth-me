use diesel::prelude::*;
use bcrypt::{hash, DEFAULT_COST};
use crate::models::{User, NewUser};
use crate::schema::users;

pub fn create_user(
    conn: &mut PgConnection,
    email: String,
    name: String,
    username: String,
    password: String,
) -> Result<User, Box<dyn std::error::Error>> {
    let password = hash(password.as_bytes(), DEFAULT_COST)?;

    let new_user = NewUser {
        name,
        username,
        email,
        password,
    };

    let user = diesel::insert_into(users::table)
        .values(&new_user)
        .get_result(conn)?;

    Ok(user)
}