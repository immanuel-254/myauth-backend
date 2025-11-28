-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    isactive BOOLEAN,
    isstaff BOOLEAN,
    isadmin BOOLEAN,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

Create Table IF NOT EXISTS logs(
    id INTEGER PRIMARY KEY,
    db_table TEXT NOT NULL,
    action TEXT NOT NULL,
    object_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

Create Table IF NOT EXISTS sessions(
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    key TEXT NOT NULL,
    created_at TIMESTAMP
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS logs;
DROP TABLE IF EXISTS sessions;
-- +goose StatementEnd
