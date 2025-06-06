use diesel::{ prelude::*, PgConnection };
use std::env;

use crate::{
    errors::{ HttpError, ErrorMessage },
    models::{ NewUser, UserRole },
    utils::password::hash,
};

pub fn create_initial_admin(conn: &mut PgConnection) -> Result<(), Box<dyn std::error::Error>> {
    use crate::schema::users::dsl::*;

    // Check if any admin users already exist
    let admin_count: i64 = users.filter(role.eq(UserRole::Admin)).count().get_result(conn)?;

    if admin_count > 0 {
        println!("Admin users already exist. Skipping initial admin creation.");
        return Ok(());
    }

    // Get admin credentials from environment variables
    let admin_email = env
        ::var("INITIAL_ADMIN_EMAIL")
        .unwrap_or_else(|_| "admin@mencrytoo.us".to_string());
    let admin_username = env::var("INITIAL_ADMIN_USERNAME").unwrap_or_else(|_| "admin".to_string());
    let admin_password = env
        ::var("INITIAL_ADMIN_PASSWORD")
        .expect("INITIAL_ADMIN_PASSWORD environment variable must be set");
    let admin_name = env
        ::var("INITIAL_ADMIN_NAME")
        .unwrap_or_else(|_| "System Administrator".to_string());

    // Hash the password
    let hashed_password = hash(admin_password).map_err(|_|
        HttpError::bad_request(ErrorMessage::HashingError.to_string())
    )?;

    // Create the initial admin user
    let new_admin = NewUser {
        name: admin_name.clone(),
        email: admin_email.clone(),
        username: admin_username.clone(),
        password: hashed_password,
        verified: true, // Pre-verified
        verification_token: None,
        token_expires_at: None,
        role: UserRole::Admin,
        created_by: None, // Bootstrap user
        force_password_change: true, // Force them to change the password on first login
    };

    let created_user = diesel
        ::insert_into(users)
        .values(&new_admin)
        .get_result::<crate::models::User>(conn)?;

    println!("✅ Initial admin user created successfully!");
    println!("   Email: {}", admin_email);
    println!("   Username: {}", admin_username);
    println!("   ID: {}", created_user.id);
    println!("⚠️ Please log in and change the password immediately!");

    Ok(())
}

// Call this function during application startup or as a separate command
pub fn run_initial_setup() -> Result<(), Box<dyn std::error::Error>> {
    // establish a database connection here
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let mut conn = PgConnection::establish(&database_url)?;

    create_initial_admin(&mut conn)?;

    Ok(())
}
