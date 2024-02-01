use crate::err::Res;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode};
use sqlx::{migrate, SqlitePool};
use std::str::FromStr;

pub async fn get_con_pool(db_path: &str) -> Res<SqlitePool> {
    let opt = SqliteConnectOptions::from_str(db_path)?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Delete);
    let pool = SqlitePool::connect_with(opt).await?;

    migrate!().run(&pool).await?;
    Ok(pool)
}
