use diesel::prelude::*;
use uuid::Uuid;
use chrono::{ Utc, NaiveDateTime };

use crate::{
    config::{ ConfigError, database::PgPool },
    models::{ User, PendingUser, NewPendingUser },
};

pub struct PendingUserRepository;

impl PendingUserRepository {
    pub fn create_pending_user(
        pool: &PgPool,
        pending_user_data: NewPendingUser
    ) -> Result<PendingUser, ConfigError> {
        let mut conn = pool.get()?;
        use crate::schema::pending_users::dsl::*;

        let pending_user = diesel
            ::insert_into(pending_users)
            .values(&pending_user_data)
            .returning(PendingUser::as_returning())
            .get_result(&mut conn)?;

        Ok(pending_user)
    }

    pub fn get_pending_user_by_token(
        pool: &PgPool,
        token_str: &str
    ) -> Result<Option<PendingUser>, ConfigError> {
        let mut conn = pool.get()?;
        use crate::schema::pending_users::dsl::*;

        let result = pending_users
            .filter(verification_token.eq(token_str))
            .first::<PendingUser>(&mut conn)
            .optional()?;

        Ok(result)
    }

    pub fn get_pending_user_by_email(
        pool: &PgPool,
        email_str: &str
    ) -> Result<Option<PendingUser>, ConfigError> {
        let mut conn = pool.get()?;
        use crate::schema::pending_users::dsl::*;

        let result = pending_users
            .filter(email.eq(email_str))
            .first::<PendingUser>(&mut conn)
            .optional()?;

        Ok(result)
    }

    /// Get pending users that are about to expire (for notification purposes)
    pub fn get_expiring_pending_users(
        pool: &PgPool,
        hours_before_expiry: i64
    ) -> Result<Vec<PendingUser>, ConfigError> {
        let mut conn = pool.get()?;
        use crate::schema::pending_users::dsl::*;

        let threshold = Utc::now().naive_utc() + chrono::Duration::hours(hours_before_expiry);

        let result = pending_users
            .filter(token_expires_at.lt(threshold))
            .filter(token_expires_at.gt(Utc::now().naive_utc())) // Not already expired
            .load::<PendingUser>(&mut conn)?;

        Ok(result)
    }

    /// Update verification token for existing pending user (useful for resend with new token)
    pub fn update_verification_token(
        pool: &PgPool,
        user_id: Uuid,
        new_token: String,
        new_expires_at: NaiveDateTime
    ) -> Result<(), ConfigError> {
        let mut conn = pool.get()?;
        use crate::schema::pending_users::dsl::*;

        diesel
            ::update(pending_users.filter(id.eq(user_id)))
            .set((verification_token.eq(new_token), token_expires_at.eq(new_expires_at)))
            .execute(&mut conn)?;

        Ok(())
    }

    pub fn delete_pending_user(pool: &PgPool, user_id: Uuid) -> Result<(), ConfigError> {
        let mut conn = pool.get()?;
        use crate::schema::pending_users::dsl::*;

        diesel::delete(pending_users.filter(id.eq(user_id))).execute(&mut conn)?;

        Ok(())
    }

    pub fn cleanup_expired_pending_users(pool: &PgPool) -> Result<usize, ConfigError> {
        let mut conn = pool.get()?;
        use crate::schema::pending_users::dsl::*;
        let now = Utc::now().naive_utc();

        let deleted_count = diesel
            ::delete(pending_users.filter(token_expires_at.lt(now)))
            .execute(&mut conn)?;

        Ok(deleted_count)
    }

    // Check if email or username exists in either pending_users or users tables
    pub fn check_user_exists_comprehensive(
        pool: &PgPool,
        email_check: &str,
        username_check: &str
    ) -> Result<(bool, bool), ConfigError> {
        let mut conn = pool.get()?;

        // Check in users table
        use crate::schema::users::dsl as users_dsl;
        let email_exists_users = users_dsl::users
            .filter(users_dsl::email.eq(email_check))
            .first::<User>(&mut conn)
            .optional()?
            .is_some();

        let username_exists_users = users_dsl::users
            .filter(users_dsl::username.eq(username_check))
            .first::<User>(&mut conn)
            .optional()?
            .is_some();

        // Check in pending_users table
        use crate::schema::pending_users::dsl as pending_dsl;
        let email_exists_pending = pending_dsl::pending_users
            .filter(pending_dsl::email.eq(email_check))
            .first::<PendingUser>(&mut conn)
            .optional()?
            .is_some();

        let username_exists_pending = pending_dsl::pending_users
            .filter(pending_dsl::username.eq(username_check))
            .first::<PendingUser>(&mut conn)
            .optional()?
            .is_some();

        let email_exists = email_exists_users || email_exists_pending;
        let username_exists = username_exists_users || username_exists_pending;

        Ok((email_exists, username_exists))
    }

    /// Helper method to create pending user for regular signup (non-admin)
    /// This method sets default values for admin-specific fields
    pub fn create_pending_user_for_signup(
        pool: &PgPool,
        name: String,
        email: String,
        username: String,
        hashed_password: String,
        verification_token: String,
        token_expires_at: NaiveDateTime,
        role: crate::models::UserRole
    ) -> Result<PendingUser, ConfigError> {
        let pending_user_data = NewPendingUser {
            name,
            email,
            username,
            password: hashed_password,
            verification_token,
            token_expires_at,
            role,
            created_by: None, // Self signup
            send_welcome_email: true, // Regular users get welcome email
            temp_password: None,
            has_temp_password: false, // They provided their own password
            force_password_change: false,
        };

        Self::create_pending_user(pool, pending_user_data)
    }
}
