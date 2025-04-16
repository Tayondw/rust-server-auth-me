use diesel::prelude::*;
use bcrypt::{ hash, DEFAULT_COST };
use crate::models::{ User, NewUser, UpdateUser };
use crate::schema::users;

pub fn create_user(
    conn: &mut PgConnection,
    email: String,
    name: String,
    username: String,
    password: String
) -> Result<User, Box<dyn std::error::Error>> {
    let password: String = hash(password.as_bytes(), DEFAULT_COST)?;

    let new_user: NewUser = NewUser {
        name,
        username,
        email,
        password,
    };

    let user: User = diesel::insert_into(users::table).values(&new_user).get_result(conn)?;

    Ok(user)
}

pub fn update_user(
    conn: &mut PgConnection,
    user_id: i32,
    email: Option<String>,
    name: Option<String>,
    username: Option<String>,
    password: Option<String>
) -> Result<User, Box<dyn std::error::Error>> {
    let password: Option<String> = password.map(|pwd: String| hash(pwd.as_bytes(), DEFAULT_COST)).transpose()?;

    let update_user: UpdateUser = UpdateUser {
        email,
        name,
        username,
        password,
    };

    let updated_user: User = diesel
        ::update(users::table)
        .filter(users::id.eq(user_id))
        .set(&update_user)
        .get_result(conn)?;

    Ok(updated_user)
}
