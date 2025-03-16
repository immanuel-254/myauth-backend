-- name: LogCreate :exec
INSERT INTO logs (
    db_table, 
    action,
    object_id, 
    user_id, 
    created_at, 
    updated_at
    ) 
    VALUES (?, ?, ?, ?, ?, ?);

-- name: LogList :many
SELECT id, db_table, action, object_id, user_id, created_at, updated_at FROM logs
ORDER BY id ASC;
