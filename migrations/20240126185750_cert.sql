CREATE TABLE IF NOT EXISTS cert (
    cname       TEXT NOT NULL,
    fingerprint BLOB NOT NULL,
    not_before  DATETIME NOT NULL,
    not_after   DATETIME NOT NULL
);
