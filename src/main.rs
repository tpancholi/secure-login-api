use crate::handler::{login_user, profile, register_user};
use actix_cors::Cors;
use actix_web::{App, HttpServer, web};
use auth::JwtService;
use db_service::DBService;
use env_logger::Env;
use log::info;

mod auth;
mod db_service;
mod handler;
mod model;
mod password_helper;
mod schema;

pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .service(register_user)
            .service(login_user)
            .service(profile),
    );
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logger
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    info!("Starting application...");

    // Initialize JWT service from environment variables
    let jwt_config = auth::JwtConfig::from_env()
        .expect("Failed to load JWT configuration from environment variables");

    let jwt_service = web::Data::new(JwtService::new(jwt_config));

    // Initialize database service
    let db_service = web::Data::new(DBService::new());

    let app_data = web::Data::new(db_service);

    info!("Application initialized successfully");

    HttpServer::new(move || {
        App::new()
            .app_data(jwt_service.clone())
            .app_data(app_data.clone())
            .wrap(actix_web::middleware::Logger::default())
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allow_any_header()
                    .allow_any_method()
                    .supports_credentials(),
            )
            .configure(init)
    })
    .bind("127.0.0.1:9000")?
    .run()
    .await
}
