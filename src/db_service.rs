use crate::model::{Login, NewUser, Users};
use crate::schema;
use crate::schema::users::dsl::users;
use crate::schema::users::{email, id, password_hash};
use diesel::r2d2::ConnectionManager;
use diesel::result::{DatabaseErrorKind, Error};
use diesel::{PgConnection, QueryDsl, RunQueryDsl};
use dotenv::dotenv;
use std::env;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::SaltString;
use log::{error, info};
use once_cell::sync::Lazy;
use regex::Regex;
use uuid::Uuid;
use rand_core::OsRng;

pub type DBPool = r2d2::Pool<ConnectionManager<PgConnection>>;

// Static regex for email validation
static EMAIL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap()
});

#[derive(Clone)]
pub struct DBService {
    pool: DBPool,
}

impl DBService {
    pub fn new() -> DBService {
        dotenv().ok();

        let db_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

        let manager = ConnectionManager::<PgConnection>::new(db_url);

        let result = r2d2::Pool::builder()
            .build(manager)
            .expect("Failed to initialize db pool.");
        DBService { pool: result }
    }

    pub fn create_user(&self, mut new_user: NewUser) -> Result<Uuid, UserCreationError> {
        // Validate email format
        self.validate_email(&new_user.email)?;

        // Validate customer name
        self.validate_customer_name(&new_user.customer_name)?;

        // Validate password strength
        self.validate_password(&new_user.password)?;

        // Hash the password using Argon2
        let hashed_password = self.hash_password(&new_user.password)
            .map_err(|_| UserCreationError::PasswordHashingFailed)?;

        new_user.password_hash = hashed_password;

        // Get connection from pool with proper error handling
        let mut conn = self.pool.get()
            .map_err(|e| {
                error!("Failed to get database connection: {}", e);
                UserCreationError::DatabaseConnectionFailed
            })?;

        diesel::insert_into(schema::users::table)
            .values(&new_user)
            .returning(schema::users::id)
            .get_result::<Uuid>(&mut conn)
            .map_err(|e| {
                error!("Failed to insert user: {}", e);
                match e {
                    Error::DatabaseError(kind, _) => {
                        if kind == DatabaseErrorKind::UniqueViolation {
                            UserCreationError::EmailAlreadyExists
                        } else {
                            UserCreationError::DatabaseError(e.to_string())
                        }
                    }
                    _ => UserCreationError::DatabaseError(e.to_string()),
                }
            })
            .map(|user_id| {
                info!("User created successfully with ID: {}", user_id);
                user_id
            })
    }

    /// Hashes a password using Argon2
    fn hash_password(&self, password: &str) -> Result<String, Box<dyn error::Error>> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        match argon2.hash_password(password.as_bytes(), &salt) {
            Ok(hash) => Ok(hash.to_string()),
            Err(e) => Err(Box::new(e)),
        }
    }

    /// Validates email format
    fn validate_email(&self, email_str: &str) -> Result<(), UserCreationError> {
        if !EMAIL_REGEX.is_match(email_str) {
            return Err(UserCreationError::InvalidEmail);
        }

        if email_str.len() > 255 { // Use the parameter name
            return Err(UserCreationError::EmailTooLong);
        }

        Ok(())
    }

    /// Validates customer name
    fn validate_customer_name(&self, name: &str) -> Result<(), UserCreationError> {
        if name.trim().is_empty() {
            return Err(UserCreationError::InvalidCustomerName);
        }

        if name.len() > 255 {
            return Err(UserCreationError::CustomerNameTooLong);
        }

        Ok(())
    }

    /// Validates password strength
    fn validate_password(&self, password: &str) -> Result<(), UserCreationError> {
        if password.len() < 8 {
            return Err(UserCreationError::WeakPassword("Password must be at least 8 characters long".to_string()));
        }

        let has_uppercase = password.chars().any(|c| c.is_uppercase());
        let has_lowercase = password.chars().any(|c| c.is_lowercase());
        let has_digit = password.chars().any(|c| c.is_numeric());
        let has_special = password.chars().any(|c| !c.is_alphanumeric());

        if !(has_uppercase && has_lowercase && has_digit && has_special) {
            return Err(UserCreationError::WeakPassword(
                "Password must contain uppercase, lowercase, numbers, and special characters".to_string()
            ));
        }

        Ok(())
    }

    pub fn login(&self, login: Login) -> Option<Users> {
        let mut conn = self.pool.get().ok()?;
        let user = users
            .filter(email.eq(&login.email))
            .first::<Users>(&mut conn)
            .ok()?;

        let parsed_hash = PasswordHash::new(&user.password_hash).ok()?;
        let argon2 = Argon2::default();

        if argon2.verify_password(login.password.as_bytes(), &parsed_hash).is_ok() {
            Some(user)
        } else {
            None
        }
    }

    pub fn get_user_by_id(&self, user_id: Uuid) -> Option<Users> {
        let mut conn = self.pool.get().ok()?;
        users
            .filter(id.eq(user_id))
            .first::<Users>(&mut conn)
            .ok()
    }
}

#[derive(Debug)]
pub enum UserCreationError {
    InvalidEmail,
    EmailTooLong,
    InvalidCustomerName,
    CustomerNameTooLong,
    WeakPassword(String),
    EmailAlreadyExists,
    PasswordHashingFailed,
    DatabaseConnectionFailed,
    DatabaseError(String),
}

impl std::fmt::Display for UserCreationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserCreationError::InvalidEmail => write!(f, "Invalid email format"),
            UserCreationError::EmailTooLong => write!(f, "Email is too long"),
            UserCreationError::InvalidCustomerName => write!(f, "Customer name cannot be empty"),
            UserCreationError::CustomerNameTooLong => write!(f, "Customer name is too long"),
            UserCreationError::WeakPassword(msg) => write!(f, "Weak password: {}", msg),
            UserCreationError::EmailAlreadyExists => write!(f, "Email already registered"),
            UserCreationError::PasswordHashingFailed => write!(f, "Failed to hash password"),
            UserCreationError::DatabaseConnectionFailed => write!(f, "Database connection failed"),
            UserCreationError::DatabaseError(err) => write!(f, "Database error: {}", err),
        }
    }
}

impl std::error::Error for UserCreationError {}
