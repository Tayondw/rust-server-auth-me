-- This file should undo anything in `up.sql`
ALTER TABLE users
DROP COLUMN is_verified,
DROP COLUMN verification_token;
