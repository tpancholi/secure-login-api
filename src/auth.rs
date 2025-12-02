use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize, Serialize, Debug)]
pub struct Claims {
    pub sub: Uuid,
    pub exp: usize,
    pub iat: usize,
    pub jti: Uuid,
}

impl Claims {
    pub fn new(user_id: Uuid, expiration_hours: i64) -> Self {
        let now = Utc::now();
        let issued_at = now.timestamp() as usize;
        let expiration = (now + Duration::hours(expiration_hours)).timestamp() as usize;
        Self {
            sub: user_id,
            exp: expiration,
            iat: issued_at,
            jti: Uuid::new_v4(),
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() as usize > self.exp
    }
}

// JWT config
pub struct JwtConfig {
    pub secret: String,
    pub expiration_hours: i64,
    pub leeway_seconds: u64,
}

impl JwtConfig {
    pub fn new(secret: String, expiration_hours: i64) -> Self {
        Self {
            secret,
            expiration_hours,
            leeway_seconds: 30,
        }
    }
}

pub struct JwtService {
    config: JwtConfig,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl JwtService {
    pub fn new(config: JwtConfig) -> Self {
        let encoding_key = EncodingKey::from_secret(config.secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(config.secret.as_bytes());
        Self {
            config,
            encoding_key,
            decoding_key,
        }
    }

    // Generate a new JWT token for a user
    pub fn generate_token(&self, user_id: Uuid) -> Result<String, jsonwebtoken::errors::Error> {
        let claims = Claims::new(user_id, self.config.expiration_hours);
        encode(&Header::default(), &claims, &self.encoding_key)
    }

    // Decode and validate JWT token
    pub fn decode_token(
        &self,
        token: &str,
    ) -> Result<TokenData<Claims>, jsonwebtoken::errors::Error> {
        let mut validation = Validation::default();
        validation.leeway = self.config.leeway_seconds;
        decode::<Claims>(token, &self.decoding_key, &validation)
    }

    // simple validation check
    pub fn is_valid_token(&self, token: &str) -> bool {
        self.decode_token(token).is_ok()
    }

    // extract user id from token if valid
    pub fn get_user_id(&self, token: &str) -> Option<Uuid> {
        self.decode_token(token)
            .ok()
            .map(|token_data| token_data.claims.sub)
    }

    // refresh token (returns a new token if current one is valid)
    pub fn refresh_token(&self, token: &str) -> Result<String, jsonwebtoken::errors::Error> {
        let token_data = self.decode_token(token)?;
        let user_id = token_data.claims.sub;
        self.generate_token(user_id)
    }
}
