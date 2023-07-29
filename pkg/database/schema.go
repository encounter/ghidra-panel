package database

const migrations = `
CREATE TABLE IF NOT EXISTS passwords (
	id UNSIGNED BIG INT PRIMARY KEY,
	username TEXT NOT NULL,
	hash BLOB NOT NULL,
	salt BLOB NOT NULL,
	format SHORT INT NOT NULL,
	updated_at INTEGER DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_passwords_username ON passwords (username);
`
