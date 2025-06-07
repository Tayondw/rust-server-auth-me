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
    send_welcome_email BOOLEAN NOT NULL DEFAULT FALSE,
    temp_password TEXT,
    has_temp_password BOOLEAN NOT NULL DEFAULT FALSE,
    force_password_change BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX idx_pending_users_email ON pending_users(email);
CREATE INDEX idx_pending_users_username ON pending_users(username);
CREATE INDEX idx_pending_users_verification_token ON pending_users(verification_token);
CREATE INDEX idx_pending_users_token_expires_at ON pending_users(token_expires_at);