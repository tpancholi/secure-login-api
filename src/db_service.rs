use crate::model::{Login, NewUser, Users};
use crate::password_helper::{PasswordConfig, PasswordError, PasswordService};
use crate::schema;
use crate::schema::users::dsl::users;
use crate::schema::users::{email, id, password_hash};
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use diesel::r2d2::ConnectionManager;
use diesel::result::{DatabaseErrorKind, Error};
use diesel::{PgConnection, QueryDsl, RunQueryDsl};
use dotenv::dotenv;
use log::{error, info};
use once_cell::sync::Lazy;
use rand_core::OsRng;
use regex::Regex;
use std::env;
use uuid::Uuid;

pub type DBPool = r2d2::Pool<ConnectionManager<PgConnection>>;

// Static regex for email validation
static EMAIL_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap());

#[derive(Clone)]
pub struct DBService {
    pool: DBPool,
    password_service: PasswordService,
}

impl DBService {
    pub fn new() -> DBService {
        dotenv().ok();

        let db_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

        let manager = ConnectionManager::<PgConnection>::new(db_url);

        let pool = r2d2::Pool::builder()
            .build(manager)
            .expect("Failed to initialize db pool.");

        // Configure password service (could load from env vars)
        let password_config = PasswordConfig {
            min_length: 8,
            require_uppercase: true,
            require_lowercase: true,
            require_digits: true,
            require_special: true,
        };
        let password_service = PasswordService::new(password_config);

        DBService {
            pool,
            password_service,
        }
    }

    pub fn create_user(&self, mut new_user: NewUser) -> Result<Uuid, UserCreationError> {
        let normalized_email = new_user.email.trim().to_lowercase();
        // Validate email format
        self.validate_email(&normalized_email)?;
        new_user.email = normalized_email;

        let normalized_name = new_user.customer_name.trim().to_string();

        if normalized_name.is_empty() {
            return Err(UserCreationError::InvalidCustomerName);
        }

        // Validate customer name
        self.validate_customer_name(&normalized_name)?;

        new_user.customer_name = normalized_name;

        // Validate password strength
        self.password_service
            .validate_password_strength(&new_user.password)
            .map_err(|errors| UserCreationError::WeakPassword(errors.join(", ")))?;

        // Use password service for hashing
        let hashed_password = self
            .password_service
            .hash_password(&new_user.password)
            .map_err(|_| UserCreationError::PasswordHashingFailed)?;

        new_user.password_hash = hashed_password;

        // Get connection from pool with proper error handling
        let mut conn = self.pool.get().map_err(|e| {
            error!("Failed to get database connection: {}", e);
            UserCreationError::DatabaseConnectionFailed
        })?;

        diesel::insert_into(schema::users::table)
            .values(&new_user)
            .returning(id)
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

    /// Validates email format
    fn validate_email(&self, email_str: &str) -> Result<(), UserCreationError> {
        let trimmed_email = email_str.trim();
        if trimmed_email.is_empty() {
            return Err(UserCreationError::InvalidEmail);
        }
        if !EMAIL_REGEX.is_match(trimmed_email) {
            return Err(UserCreationError::InvalidEmail);
        }

        if trimmed_email.len() > 255 {
            // Use the parameter name
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

    pub fn login(&self, login: Login) -> Option<Users> {
        let mut conn = self.pool.get().ok()?;
        let user = users
            .filter(email.eq(&login.email))
            .first::<Users>(&mut conn)
            .ok()?;

        // Use password service for verification
        match self
            .password_service
            .verify_password(&login.password, &user.password_hash)
        {
            Ok(true) => Some(user),
            _ => None,
        }
    }

    pub fn get_user_by_id(&self, user_id: Uuid) -> Option<Users> {
        let mut conn = self.pool.get().ok()?;
        users.filter(id.eq(user_id)).first::<Users>(&mut conn).ok()
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
