use diesel::prelude::*;
use crate::models::NewUser;
use crate::schema::users;
use bcrypt::{hash, DEFAULT_COST};

pub fn seed_users(conn: &mut PgConnection) -> QueryResult<()> {
    // First clear the table to avoid duplicates
    diesel::delete(users::table).execute(conn)?;

    let new_users = vec![
        NewUser {
            name: "John Doe".to_string(),
            username: "johndoe".to_string(),
            email: "john@example.com".to_string(),
            password: hash("abc123", DEFAULT_COST).unwrap(),
        },
        NewUser {
            name: "Jane Smith".to_string(),
            username: "janesmith".to_string(),
            email: "jane@example.com".to_string(),
            password: hash("lmnop567", DEFAULT_COST).unwrap()
        },
    ];

    diesel::insert_into(users::table)
        .values(&new_users)
        .execute(conn)?;

    Ok(())
}