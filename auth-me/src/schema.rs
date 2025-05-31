// @generated automatically by Diesel CLI.

pub mod sql_types {
    #[derive(Clone, diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "user_role"))]
    pub struct UserRole;
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::UserRole;

    pending_users (id) {
        id -> Uuid,
        name -> Varchar,
        email -> Varchar,
        username -> Varchar,
        password -> Varchar,
        verification_token -> Varchar,
        token_expires_at -> Timestamp,
        role -> UserRole,
        created_by -> Nullable<Uuid>,
        force_password_change -> Bool,
        created_at -> Nullable<Timestamp>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::UserRole;

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
        role -> UserRole,
        created_by -> Nullable<Uuid>,
        force_password_change -> Bool,
        created_at -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::joinable!(pending_users -> users (created_by));

diesel::allow_tables_to_appear_in_same_query!(
    pending_users,
    users,
);
