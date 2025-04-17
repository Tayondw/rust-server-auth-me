-- This file should undo anything in `up.sql`
ALTER TABLE posts
DROP CONSTRAINT fk_user,
DROP COLUMN user_id;

