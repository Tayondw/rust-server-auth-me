use diesel::prelude::*;
use uuid::Uuid;
use crate::{ models::{ NewUser, UpdateUser, User }, schema::users::{ self } };

// CREATE USER
pub fn create_user(
    conn: &mut PgConnection,
    name: String,
    email: String,
    username: String,
    password: String,
    verified: bool,
) -> Result<User, Box<dyn std::error::Error>> {
    let token: Option<String> = Some(Uuid::new_v4().to_string());

    let new_user: NewUser = NewUser {
        name,
        email,
        username,
        password,
        verified,
        verification_token: token,
    };

    let user: User = diesel::insert_into(users::table).values(&new_user).get_result(conn)?;

    Ok(user)
}

// UPDATE USER
pub fn update_user(
    conn: &mut PgConnection,
    user_id: Uuid,
    email: Option<String>,
    name: Option<String>,
    username: Option<String>,
    password: Option<String>
) -> Result<User, Box<dyn std::error::Error>> {
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
    user_id: Uuid
) -> Result<(), diesel::result::Error> {
    use crate::schema::users::dsl::*;

    diesel::delete(users.find(user_id)).execute(conn)?;

    Ok(())
}
