use diesel::prelude::*;
use crate::models::{ Post, NewPost, UpdatePost };
use crate::schema::posts::{ self, user_id };

// GET POST BY USER
pub fn get_posts_by_user(
    conn: &mut PgConnection,
    user: i32,
    limit_val: i64,
    offset_val: i64,
    sort_order: Option<String>
) -> Result<Vec<Post>, Box<dyn std::error::Error>> {
    use crate::schema::posts::dsl::*;

    let mut query = posts.filter(user_id.eq(user)).into_boxed();

    if let Some(order) = sort_order {
        match order.as_str() {
            "asc" => {
                query = query.order(created_at.asc());
            }
            "desc" => {
                query = query.order(created_at.desc());
            }
            _ => {}
        }
    }

    let user_posts = query
        .limit(limit_val)
        .offset(offset_val)
        .select(Post::as_select())
        .load::<Post>(conn)?;

    Ok(user_posts)
}

// CREATE POST
pub fn create_post(
    conn: &mut PgConnection,
    title: String,
    content: String,
    user_id_value: i32
) -> Result<Post, Box<dyn std::error::Error>> {
    let new_post: NewPost = NewPost {
        title,
        content,
        user_id: user_id_value,
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
