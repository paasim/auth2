use crate::err::{AuthError, Res};
use crate::x509::X509Cert;
use serde::{de, ser, Deserialize, Deserializer, Serialize, Serializer};
use sqlx::{query, query_as, SqlitePool};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

fn parse_rfc3339<'de, D: Deserializer<'de>>(deserializer: D) -> Result<OffsetDateTime, D::Error> {
    let s = Deserialize::deserialize(deserializer)?;
    OffsetDateTime::parse(s, &Rfc3339).map_err(de::Error::custom)
}

fn format_rfc3339<S: Serializer>(dt: &OffsetDateTime, s: S) -> Result<S::Ok, S::Error> {
    dt.format(&Rfc3339)
        .map_err(ser::Error::custom)
        .and_then(|str| s.serialize_str(&str))
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CertInfo {
    pub cname: String,
    pub fingerprint: Vec<u8>,
    #[serde(deserialize_with = "parse_rfc3339", serialize_with = "format_rfc3339")]
    pub not_before: OffsetDateTime,
    #[serde(deserialize_with = "parse_rfc3339", serialize_with = "format_rfc3339")]
    pub not_after: OffsetDateTime,
}

#[derive(Debug, Deserialize, Serialize)]
struct CertInfoRow {
    cname: String,
    fingerprint: Vec<u8>,
    not_before: i64,
    not_after: i64,
}

impl TryFrom<CertInfoRow> for CertInfo {
    type Error = AuthError;

    fn try_from(value: CertInfoRow) -> Result<Self, Self::Error> {
        Ok(Self {
            cname: value.cname,
            fingerprint: value.fingerprint,
            not_before: OffsetDateTime::from_unix_timestamp(value.not_before)?,
            not_after: OffsetDateTime::from_unix_timestamp(value.not_after)?,
        })
    }
}

impl CertInfo {
    pub async fn insert_cert(&self, con: &SqlitePool) -> Res<u32> {
        let id_row = query!(
            r#"
                INSERT INTO cert (cname, fingerprint, not_before, not_after)
                VALUES (?, ?, ?, ?)
                RETURNING rowid AS "id: u32"
            "#,
            self.cname,
            self.fingerprint,
            self.not_before,
            self.not_after
        )
        .fetch_one(con)
        .await?;
        Ok(id_row.id)
    }

    pub async fn get_all(con: &SqlitePool) -> Res<Vec<Self>> {
        let rows = query_as!(
            CertInfoRow,
            r#"
            SELECT cname, fingerprint, not_before, not_after
            FROM cert
            ORDER BY not_before DESC
            "#,
        )
        .fetch_all(con)
        .await?;
        rows.into_iter().map(CertInfo::try_from).collect()
    }
}

impl TryFrom<&X509Cert> for CertInfo {
    type Error = AuthError;

    fn try_from(crt: &X509Cert) -> Result<Self, Self::Error> {
        Ok(Self {
            cname: crt.get_cname()?,
            fingerprint: crt.get_fingerprint()?,
            not_before: crt.get_not_before()?,
            not_after: crt.get_not_after()?,
        })
    }
}
