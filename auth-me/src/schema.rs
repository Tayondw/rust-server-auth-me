// @generated automatically by Diesel CLI.

diesel::table! {
    posts (id) {
        id -> Int4,
        #[max_length = 255]
        title -> Varchar,
        #[max_length = 255]
        content -> Varchar,
        created_at -> Timestamp,
        updated_at -> Timestamp,
    }
}

diesel::table! {
    users (id) {
        id -> Int4,
        #[max_length = 50]
        name -> Varchar,
        #[max_length = 50]
        username -> Varchar,
        #[max_length = 50]
        email -> Varchar,
        #[max_length = 50]
        password -> Varchar,
        created_at -> Timestamp,
        updated_at -> Timestamptz,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    posts,
    users,
);
