use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Queryable, Serialize, Debug)]
pub struct Users {
    pub id: Uuid,
    pub customer_name: String,
    pub email: String,
    pub password_hash: String,
    pub is_email_verified: bool,
    pub is_active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl Users {
    pub fn to_response(&self) -> ProfileDetails {
        ProfileDetails {
            customer_name: self.customer_name.clone(),
            email: self.email.clone(),
            is_email_verified: self.is_email_verified,
            is_active: self.is_active,
            created_at: self.created_at,
            updated_at: self.updated_at,
            deleted_at: self.deleted_at,
        }
    }
}

#[derive(Insertable, Deserialize)]
#[diesel(table_name = "users")]
pub struct NewUser {
    pub customer_name: String,
    pub email: String,
    pub password_hash: String,
}

#[derive(Deserialize)]
pub struct Login {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Debug)]
pub struct ProfileDetails {
    pub customer_name: String,
    pub email: String,
    pub is_email_verified: bool,
    pub is_active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
}
