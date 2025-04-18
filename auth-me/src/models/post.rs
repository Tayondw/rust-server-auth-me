use diesel::prelude::*;
use serde::{ Deserialize, Serialize };
use crate::schema::posts;

#[derive(Debug, Queryable, Serialize, Deserialize, Selectable, Identifiable)]
#[diesel(table_name = posts)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Post {
    pub id: i32,
    pub title: String,
    pub content: String,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
    pub user_id: i32,
}

#[derive(Insertable, Deserialize, Clone)]
#[diesel(table_name = posts)]
pub struct NewPost {
      pub title: String,
      pub content: String,
      pub user_id: i32,
}

#[derive(AsChangeset, Deserialize, Default)]
#[diesel(table_name = posts)]
pub struct UpdatePost {
    pub title: Option<String>,
    pub content: Option<String>,
}
