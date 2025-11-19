// @generated automatically by Diesel CLI.

diesel::table! {
    users (id) {
        id -> Uuid,
        customer_name -> Varchar,
        email -> Citext,
        password_hash -> Text,
        is_email_verified -> Bool,
        is_active -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        deleted_at -> Nullable<Timestamptz>,
    }
}
