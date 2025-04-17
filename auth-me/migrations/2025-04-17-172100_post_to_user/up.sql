-- Your SQL goes here
ALTER TABLE posts
ADD COLUMN user_id INTEGER NOT NULL,
ADD CONSTRAINT fk_user
    FOREIGN KEY (user_id)
    REFERENCES users(id)
    ON DELETE CASCADE;
