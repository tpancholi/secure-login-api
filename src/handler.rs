use crate::auth::JwtService;
use crate::db_service::DBService;
use crate::model::{Login, NewUser};
use actix_web::cookie::time::Duration;
use actix_web::cookie::{Cookie, SameSite};
use actix_web::{HttpRequest, HttpResponse, post, web};

#[post("/register")]
pub async fn register_user(db: web::Data<DBService>, user: web::Json<NewUser>) -> HttpResponse {
    let data = user.into_inner();
    match db.create_user(data).await {
        Ok(_) => HttpResponse::Ok().body("Success"),
        Err(_) => {
            eprintln!("Error creating user");
            HttpResponse::InternalServerError().body("Error creating user")
        }
    }
}

#[post("/login")]
pub async fn login_user(
    db: web::Data<DBService>,
    jwt_service: web::Data<JwtService>,
    login: web::Json<Login>,
) -> HttpResponse {
    let data = login.into_inner();
    match db.login(data).await {
        Some(detail) => match jwt_service.generate_token(detail.id) {
            Ok(token) => {
                let cookie = Cookie::build("token", token)
                    .path("/")
                    .max_age(Duration::seconds(3600))
                    .same_site(SameSite::None)
                    .http_only(true)
                    .finish();
                HttpResponse::Ok().cookie(cookie).finish()
            }
            Err(_) => HttpResponse::InternalServerError().body("Failed to generate token"),
        },
        None => HttpResponse::Unauthorized().body("Invalid credentials"),
    }
}

#[post("/profile")]
pub async fn profile(
    db: web::Data<DBService>,
    jwt_service: web::Data<JwtService>,
    req: HttpRequest,
) -> HttpResponse {
    // Extract cookie from request
    if let Some(cookie) = req.cookie("token") {
        let token_value = cookie.value().to_string();

        // Validate token
        if !jwt_service.is_valid_token(&token_value) {
            return HttpResponse::Unauthorized().body("Invalid or expired token");
        }

        // Refresh the token
        let new_token = match jwt_service.refresh_token(&token_value) {
            Ok(token) => token,
            Err(_) => {
                return HttpResponse::Unauthorized().body("Failed to refresh token");
            }
        };

        // Extract user ID from token
        if let Some(user_id) = jwt_service.get_user_id(&new_token) {
            // Fetch user from database
            match db.get_user_by_id(user_id) {
                Some(user) => {
                    // Create new cookie with refreshed token
                    let new_cookie = Cookie::build("token", new_token)
                        .path("/")
                        .max_age(Duration::seconds(3600))
                        .same_site(SameSite::None)
                        .http_only(true)
                        .finish();

                    // Return user data with new token in cookie
                    HttpResponse::Ok().cookie(new_cookie).json(user)
                }
                None => HttpResponse::NotFound().body("User not found"),
            }
        } else {
            HttpResponse::Unauthorized().body("Failed to extract user information")
        }
    } else {
        HttpResponse::Unauthorized().body("Missing authentication token")
    }
}
