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

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct CertInfo {
    cname: String,
    fingerprint: Vec<u8>,
    #[serde(deserialize_with = "parse_rfc3339", serialize_with = "format_rfc3339")]
    not_before: OffsetDateTime,
    #[serde(deserialize_with = "parse_rfc3339", serialize_with = "format_rfc3339")]
    not_after: OffsetDateTime,
}

impl CertInfo {
    pub fn cname(&self) -> &str {
        &self.cname
    }

    pub fn fingerprint(&self) -> String {
        let hex = self
            .fingerprint
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>();
        format!("{}\n{}", hex[..16].join(":"), &hex[16..32].join(":"))
    }

    pub fn not_before(&self) -> String {
        self.not_before.date().to_string()
    }

    pub fn not_after(&self) -> String {
        self.not_after.date().to_string()
    }
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
    pub async fn insert_cert(&self, con: &SqlitePool) -> Res<bool> {
        let not_before = self.not_before.unix_timestamp();
        let not_after = self.not_after.unix_timestamp();
        let res = query!(
            r#"
                INSERT INTO cert (cname, fingerprint, not_before, not_after)
                VALUES (?, ?, ?, ?)
            "#,
            self.cname,
            self.fingerprint,
            not_before,
            not_after
        )
        .execute(con)
        .await?;
        Ok(res.rows_affected() == 1)
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

#[cfg(test)]
mod tests {
    use super::*;
    use time::{Date, Month, Time};

    #[test]
    fn cert_info_parsing_works() {
        // getting the dates right is the relevant part
        let ci_json = r#"{
            "cname": "the name",
            "fingerprint": [1,2,3],
            "not_before": "1985-04-12T23:20:50Z",
            "not_after": "1990-12-31T23:59:01Z"
        }"#;
        let ci: CertInfo = serde_json::from_str(ci_json).unwrap();
        assert!(ci.cname == "the name");
        assert!(ci.fingerprint == vec![1, 2, 3]);

        let d0 = Date::from_calendar_date(1985, Month::April, 12).unwrap();
        let t0 = Time::from_hms(23, 20, 50).unwrap();
        let dt0 = OffsetDateTime::new_utc(d0, t0);
        assert_eq!(ci.not_before, dt0);

        let d1 = Date::from_calendar_date(1990, Month::December, 31).unwrap();
        let t1 = Time::from_hms(23, 59, 1).unwrap();
        let dt1 = OffsetDateTime::new_utc(d1, t1);
        assert_eq!(ci.not_after, dt1);

        let ci_json = serde_json::to_string(&ci).unwrap();
        let ci2: CertInfo = serde_json::from_str(&ci_json).unwrap();
        assert_eq!(ci, ci2);
    }
}
