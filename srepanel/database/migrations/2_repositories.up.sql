CREATE TABLE repositories (
    id UNSIGNED BIG INT PRIMARY KEY,
    name TEXT NOT NULL,
    webhook_url TEXT,
    updated_at INTEGER DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE UNIQUE INDEX idx_repositories_name ON repositories (name);
