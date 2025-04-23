pub mod users;
pub mod posts;
pub mod requests;

pub use requests::{
    CreateUserRequest,
    CreatePostRequest,
    UpdateUserRequest,
    UpdatePostRequest,
    PostQuery,
};
