// @generated automatically by Diesel CLI.

pub mod sql_types {
    #[derive(diesel::query_builder::QueryId, Clone, diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "user_role"))]
    pub struct UserRole;
}

diesel::table! {
    use diesel::sql_types::*;
    use crate::models::UserRoleType;

    users (id) {
        id -> Uuid,
        #[max_length = 100]
        name -> Varchar,
        #[max_length = 255]
        email -> Varchar,
        #[max_length = 50]
        username -> Varchar,
        #[max_length = 255]
        password -> Varchar,
        verified -> Bool,
        #[max_length = 255]
        verification_token -> Nullable<Varchar>,
        token_expires_at -> Nullable<Timestamptz>,
        role -> UserRoleType,
        created_at -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
    }
}
