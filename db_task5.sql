ALTER TABLE application
    ADD COLUMN username VARCHAR(64) UNIQUE,
ADD COLUMN password_hash CHAR(64);