CREATE TYPE user_role AS ENUM ('admin', 'user');
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users (
    id UUID NOT NULL PRIMARY KEY DEFAULT (uuid_generate_v4()),
    name VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    verification_token VARCHAR(255),
    token_expires_at TIMESTAMP WITH TIME ZONE,
    role user_role NOT NULL DEFAULT 'user',
    created_by UUID REFERENCES users(id),
    force_password_change BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX users_email_idx ON users (email);