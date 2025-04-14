-- This file should undo anything in `up.sql`
ALTER TABLE users
ALTER COLUMN password TYPE VARCHAR(50);
