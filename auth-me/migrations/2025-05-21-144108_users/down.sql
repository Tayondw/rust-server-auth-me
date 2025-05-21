-- This file should undo anything in `up.sql`
DROP TABLE IF EXISTS "users";

DROP TYPE IF EXISTS user_role;

DROP EXTENSION IF EXISTS "uuid-ossp";