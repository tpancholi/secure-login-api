use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use rand_core::OsRng;

#[derive(Debug)]
pub enum PasswordError {
    HashingFailed,
    VerificationFailed,
}

impl std::fmt::Display for PasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasswordError::HashingFailed => write!(f, "Failed to hash password"),
            PasswordError::VerificationFailed => write!(f, "Failed to verify password"),
        }
    }
}

impl std::error::Error for PasswordError {}

#[derive(Clone)]
pub struct PasswordConfig {
    pub min_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digits: bool,
    pub require_special: bool,
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self {
            min_length: 8,
            require_uppercase: true,
            require_lowercase: true,
            require_digits: true,
            require_special: true,
        }
    }
}

#[derive(Clone)]
pub struct PasswordService {
    config: PasswordConfig,
}

impl PasswordService {
    pub fn new(config: PasswordConfig) -> Self {
        Self { config }
    }

    pub fn hash_password(&self, password: &str) -> Result<String, PasswordError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|_| PasswordError::HashingFailed)
    }

    pub fn verify_password(&self, password: &str, hash: &str) -> Result<bool, PasswordError> {
        let parsed_hash = PasswordHash::new(hash).map_err(|_| PasswordError::VerificationFailed)?;

        let argon2 = Argon2::default();
        argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .map(|_| true)
            .map_err(|_| PasswordError::VerificationFailed)
    }

    pub fn validate_password_strength(&self, password: &str) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if password.len() < self.config.min_length {
            errors.push(format!(
                "Password must be at least {} characters long",
                self.config.min_length
            ));
        }

        if self.config.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
            errors.push("Password must contain at least one uppercase letter".to_string());
        }

        if self.config.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
            errors.push("Password must contain at least one lowercase letter".to_string());
        }

        if self.config.require_digits && !password.chars().any(|c| c.is_numeric()) {
            errors.push("Password must contain at least one digit".to_string());
        }

        if self.config.require_special && password.chars().all(|c| c.is_alphanumeric()) {
            errors.push("Password must contain at least one special character".to_string());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}
