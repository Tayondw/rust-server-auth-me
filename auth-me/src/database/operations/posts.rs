use diesel::prelude::*;
use crate::models::{ Post, NewPost, UpdatePost };
use crate::schema::posts;

// CREATE POST
pub fn create_post(
    conn: &mut PgConnection,
    title: String,
    content: String
) -> Result<Post, Box<dyn std::error::Error>> {
    let new_post: NewPost = NewPost {
        title,
        content,
    };

    let post: Post = diesel::insert_into(posts::table).values(&new_post).get_result(conn)?;

    Ok(post)
}

// UPDATE POST
pub fn update_post(
    conn: &mut PgConnection,
    post_id: i32,
    title: Option<String>,
    content: Option<String>
) -> Result<Post, Box<dyn std::error::Error>> {
    
    let update_post: UpdatePost = UpdatePost {
        title,
        content,
    };

    let updated_post: Post = diesel
        ::update(posts::table)
        .filter(posts::id.eq(post_id))
        .set(&update_post)
        .get_result(conn)?;

    Ok(updated_post)
}

// DELETE POST
pub async fn delete_post(
    conn: &mut PgConnection,
    post_id: i32
) -> Result<(), diesel::result::Error> {
    use crate::schema::posts::dsl::*;

    diesel::delete(posts.find(post_id)).execute(conn)?;

    Ok(())
}
