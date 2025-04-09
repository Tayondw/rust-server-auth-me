use diesel::prelude::*;
use super::users::seed_users;

pub struct DatabaseSeeder {
    conn: &'static mut PgConnection,
}

impl DatabaseSeeder {
    pub fn new(conn: &'static mut PgConnection) -> Self {
        DatabaseSeeder { conn }
    }

    pub fn run(&mut self) -> QueryResult<()> {
        seed_users(&mut self.conn)?;
        // Add more seed calls as needed
        Ok(())
    }
}