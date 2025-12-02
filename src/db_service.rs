use crate::model::{Login, NewUser, Users};
use crate::schema;
use crate::schema::users::dsl::users;
use crate::schema::users::{email, id, password_hash};
use diesel::r2d2::ConnectionManager;
use diesel::result::Error;
use diesel::{PgConnection, QueryDsl, RunQueryDsl};
use dotenv::dotenv;
use std::env;
use uuid::Uuid;

pub type DBPool = r2d2::Pool<ConnectionManager<PgConnection>>;

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

    pub fn create_user(&self, new_user: NewUser) -> Result<(), Error> {
        diesel::insert_into(schema::users::table)
            .values(&new_user)
            .execute(&mut self.pool.get().unwrap())?;
        Ok(())
    }

    pub fn login(&self, login: Login) -> Option<Users> {
        // TODO: convert login password to from simple text to hash
        users
            .filter(email.eq(login.email))
            .filter(password_hash.eq(login.password))
            .first::<Users>(&mut self.pool.get().unwrap())
            .ok()
    }

    pub fn get_user_by_id(&self, user_id: Uuid) -> Option<Users> {
        users
            .filter(id.eq(user_id))
            .first::<Users>(&mut self.pool.get().unwrap())
            .ok()
    }
}
