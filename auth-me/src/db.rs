use diesel::prelude::*;

// established a connection to the database
// if connection fails, panic
pub fn establish_connection(database_url: &str) -> PgConnection {
    PgConnection::establish(database_url)
        .unwrap_or_else(|_| panic!("Error connecting to {}", database_url))
}