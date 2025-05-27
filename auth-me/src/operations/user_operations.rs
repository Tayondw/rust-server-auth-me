use diesel::prelude::*;
use uuid::Uuid;
use chrono::NaiveDateTime;

use crate::{ models::{ NewUser, User, UserRole }, schema::users::{ self } };

// CREATE USER
pub fn create_user(
    conn: &mut PgConnection,
    name: String,
    email: String,
    username: String,
    password: String,
    verified: bool,
    token_expires_at: Option<NaiveDateTime>,
    role: UserRole
) -> Result<User, Box<dyn std::error::Error>> {
    let token: Option<String> = Some(Uuid::new_v4().to_string());

    let new_user: NewUser = NewUser {
        name,
        email,
        username,
        password,
        verified,
        verification_token: token,
        token_expires_at,
        role,
    };

    let user: User = diesel::insert_into(users::table).values(&new_user).get_result(conn)?;

    Ok(user)
}

// DELETE USER
pub async fn delete_user(
    conn: &mut PgConnection,
    user_id: Uuid
) -> Result<(), diesel::result::Error> {
    use crate::schema::users::dsl::*;

    diesel::delete(users.find(user_id)).execute(conn)?;

    Ok(())
}
