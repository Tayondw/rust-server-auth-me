CREATE TABLE pending_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR NOT NULL,
    email VARCHAR NOT NULL,
    username VARCHAR NOT NULL,
    password VARCHAR NOT NULL,
    verification_token VARCHAR NOT NULL UNIQUE,
    token_expires_at TIMESTAMP NOT NULL,
    role user_role NOT NULL DEFAULT 'user',
    created_by UUID REFERENCES users(id),
    force_password_change BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX pending_users_email_idx ON pending_users(email);
CREATE INDEX pending_users_username_idx ON pending_users(username);
CREATE INDEX pending_users_verification_token_idx ON pending_users(verification_token);
CREATE INDEX pending_users_token_expires_at_idx ON pending_users(token_expires_at);