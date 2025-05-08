use diesel::prelude::*;
use bcrypt::{ hash, DEFAULT_COST };
use uuid::Uuid;
use crate::{models::{ NewUser, UpdateUser, User }, schema::users::{self}};

// CREATE USER
pub fn create_user(
    conn: &mut PgConnection,
    email: String,
    name: String,
    username: String,
    password: String
) -> Result<User, Box<dyn std::error::Error>> {
    let token = Some(Uuid::new_v4().to_string());

    let new_user: NewUser = NewUser {
        name,
        username,
        email,
        password,
        is_verified: false,
        verification_token: token,
    };

    let user: User = diesel::insert_into(users::table).values(&new_user).get_result(conn)?;

    Ok(user)
}

// UPDATE USER
pub fn update_user(
    conn: &mut PgConnection,
    user_id: i32,
    email: Option<String>,
    name: Option<String>,
    username: Option<String>,
    password: Option<String>
) -> Result<User, Box<dyn std::error::Error>> {
    let password: Option<String> = password
        .map(|pwd: String| hash(pwd.as_bytes(), DEFAULT_COST))
        .transpose()?;

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

// DELETE USER
pub async fn delete_user(
    conn: &mut PgConnection,
    user_id: i32
) -> Result<(), diesel::result::Error> {
    use crate::schema::users::dsl::*;

    diesel::delete(users.find(user_id)).execute(conn)?;

    Ok(())
}
