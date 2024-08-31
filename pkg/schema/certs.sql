-- name: FindCertByID :one
SELECT
    *
FROM
    certs
WHERE
    id = $1;

-- name: CreateCert :one
INSERT INTO
    certs (id, der)
VALUES
    ($1, $2) RETURNING *;
