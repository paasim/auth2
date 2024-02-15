CREATE TABLE IF NOT EXISTS cert (
    cname       TEXT NOT NULL,
    fingerprint BLOB NOT NULL,
    not_before  INTEGER NOT NULL,
    not_after   INTEGER NOT NULL
) STRICT;
