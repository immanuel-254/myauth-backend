-- name: SessionCreate :one
INSERT INTO sessions (
    key,
    user_id, 
    created_at
    ) 
    VALUES (?, ?, ?)
    RETURNING id, key, user_id, created_at;

-- name: SessionRead :one
SELECT id, key, user_id ,created_at FROM sessions
WHERE key = ?;

-- name: SessionList :many
SELECT id, key, user_id, created_at FROM sessions
ORDER BY id ASC;

-- name: SessionDelete :exec
DELETE FROM sessions WHERE key = ?;
