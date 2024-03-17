use crate::err::Res;
use crate::es256::Es256Pub;
use crate::{base64::base64url_encode, err::AuthError};
use openssl::rand::rand_bytes;
use serde::Deserialize;
use sqlx::{query, SqlitePool};

#[derive(Deserialize)]
pub struct User {
    name: String,
}

impl User {
    pub async fn get_pk(&self, pool: &SqlitePool) -> Res<Vec<String>> {
        let id_row = query!(
            r#"
            SELECT cred_id
            FROM user_credential
            INNER JOIN user USING(user_id)
            WHERE user_name = ?"#,
            self.name
        )
        .fetch_all(pool)
        .await?;
        Ok(id_row
            .into_iter()
            .map(|r| base64url_encode(r.cred_id))
            .collect())
    }

    pub async fn get_id(&self, pool: &SqlitePool) -> Res<[u8; 8]> {
        let q = query!(r#"SELECT user_id FROM user WHERE user_name = ?"#, self.name);
        match q.fetch_one(pool).await {
            Ok(id_row) => Ok(id_row.user_id.to_be_bytes()),
            Err(e) => Err(AuthError::DbNotFound(e)),
        }
    }

    pub async fn new_id(pool: &SqlitePool) -> Res<[u8; 8]> {
        let mut id = [0; 8];
        for _ in 0..10 {
            rand_bytes(&mut id)?;
            let id_i64 = i64::from_be_bytes(id);
            if query!(r#"SELECT user_id FROM user WHERE user_id = ?"#, id_i64)
                .fetch_optional(pool)
                .await?
                .is_none()
            {
                return Ok(id);
            }
        }
        Err("unable to get new user id")?
    }

    pub async fn insert(id: [u8; 8], name: &str, pool: &SqlitePool) -> Res<bool> {
        let id_i64 = i64::from_be_bytes(id);
        let q = query!(
            r#"INSERT INTO user (user_id, user_name) VALUES (?, ?)"#,
            id_i64,
            name
        );

        match q.execute(pool).await {
            Ok(r) => Ok(r.rows_affected() == 1),
            Err(e) => Err(AuthError::DbAlreadyExists(e)),
        }
    }
}

pub struct UserCredential {
    user_id: [u8; 8],
    cred_id: Vec<u8>,
}

impl UserCredential {
    pub fn new(user_id: [u8; 8], cred_id: Vec<u8>) -> Self {
        Self { user_id, cred_id }
    }

    pub fn user_id(&self) -> [u8; 8] {
        self.user_id
    }

    pub async fn get_pk(&self, pool: &SqlitePool) -> Res<Es256Pub> {
        let user_id = i64::from_be_bytes(self.user_id);
        let q = query!(
            r#"SELECT cred_pk FROM user_credential WHERE user_id = ? AND cred_id = ?"#,
            user_id,
            self.cred_id
        );
        match q.fetch_one(pool).await {
            Ok(r) => Es256Pub::from_der(r.cred_pk),
            Err(e) => Err(AuthError::DbNotFound(e)),
        }
    }

    pub async fn insert(&self, cred_pk: &Es256Pub, pool: &SqlitePool) -> Res<bool> {
        let user_id = i64::from_be_bytes(self.user_id);
        let cred_pk = cred_pk.to_der()?;
        let q = query!(
            r#" INSERT INTO user_credential (user_id, cred_id, cred_pk)
                VALUES (?, ?, ?)
            "#,
            user_id,
            self.cred_id,
            cred_pk,
        );
        match q.execute(pool).await {
            Ok(r) => Ok(r.rows_affected() == 1),
            Err(e) => Err(AuthError::DbAlreadyExists(e)),
        }
    }
}
