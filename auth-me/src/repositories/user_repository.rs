use diesel::prelude::*;
use uuid::Uuid;
use chrono::{ NaiveDateTime, Utc };

use crate::{
    config::{ ConfigError, database::PgPool },
    models::{ User, UserRole, UpdateUser, NewUser },
    dto::{user_dtos::{
        UserQuery,
        UpdateUserRequest,
        AdvancedUserFilters,
        UserSortBy,
        UserStatistics,
        CreateUserRequest,
    }, create_user::CreateUserParams},
    schema::users::{ self, dsl::* },
};

pub struct UserRepository;

impl UserRepository {
    pub fn create_user(
        conn: &mut PgConnection,
        request: CreateUserRequest
    ) -> Result<User, ConfigError> {
        let token: Option<String> = Some(Uuid::new_v4().to_string());

        let new_user = NewUser {
            name: request.name,
            email: request.email,
            username: request.username,
            password: request.password,
            verified: request.verified,
            verification_token: token,
            token_expires_at: request.token_expires_at,
            role: request.role,
        };

        let user = diesel::insert_into(users::table).values(&new_user).get_result(conn)?;

        Ok(user)
    }

    /// Unified user creation method
    pub fn create_user_unified(
        conn: &mut PgConnection,
        params: CreateUserParams
    ) -> Result<User, ConfigError> {
        let other_verification_token = if params.verified {
            None // No token needed for pre-verified users
        } else {
            Some(Uuid::new_v4().to_string())
        };

        let new_user = NewUser {
            name: params.name,
            email: params.email,
            username: params.username,
            password: params.password,
            verified: params.verified,
            verification_token: other_verification_token,
            token_expires_at: params.token_expires_at,
            role: params.role,
            // Add these fields to your NewUser struct if needed
            // created_by: params.created_by,
            // force_password_change: params.force_password_change,
        };

        let user = diesel::insert_into(users::table).values(&new_user).get_result(conn)?;

        Ok(user)
    }

    /// Check if email or username already exists
    pub fn check_user_exists(
        pool: &PgPool,
        email_check: &str,
        username_check: &str
    ) -> Result<(bool, bool), ConfigError> {
        let mut conn = pool.get()?;
        use crate::schema::users::dsl::*;

        let email_exists = users
            .filter(email.eq(email_check))
            .first::<User>(&mut conn)
            .optional()?
            .is_some();

        let username_exists = users
            .filter(username.eq(username_check))
            .first::<User>(&mut conn)
            .optional()?
            .is_some();

        Ok((email_exists, username_exists))
    }

    pub fn get_user(pool: &PgPool, query: UserQuery) -> Result<Option<User>, ConfigError> {
        let mut conn = pool.get()?;

        let result = match query {
            UserQuery::Id(user_id) =>
                users.filter(id.eq(user_id)).first::<User>(&mut conn).optional()?,
            UserQuery::Email(email_str) =>
                users.filter(email.eq(&email_str)).first::<User>(&mut conn).optional()?,
            UserQuery::Name(name_str) =>
                users.filter(name.eq(&name_str)).first::<User>(&mut conn).optional()?,
            UserQuery::Username(username_str) =>
                users.filter(username.eq(&username_str)).first::<User>(&mut conn).optional()?,
            UserQuery::Token(token_str) =>
                users
                    .filter(verification_token.eq(Some(token_str)))
                    .first::<User>(&mut conn)
                    .optional()?,
            UserQuery::Role(role_enum) =>
                users.filter(role.eq(role_enum)).first::<User>(&mut conn).optional()?,
        };

        Ok(result)
    }

    pub fn get_users_paginated(
        pool: &PgPool,
        page: usize,
        limit: usize
    ) -> Result<(Vec<User>, i64), ConfigError> {
        let mut conn = pool.get()?;
        let offset = (page - 1) * limit;

        let user_list = users::table
            .select(User::as_select())
            .limit(limit as i64)
            .offset(offset as i64)
            .order(users::created_at.desc())
            .load(&mut conn)?;

        let total_count: i64 = users::table.count().get_result(&mut conn)?;

        Ok((user_list, total_count))
    }

    pub fn search_users(
        pool: &PgPool,
        page: usize,
        limit: usize,
        search_term: Option<&str>,
        role_filter: Option<UserRole>,
        verified_filter: Option<bool>
    ) -> Result<(Vec<User>, i64), ConfigError> {
        let mut conn = pool.get()?;
        let offset = (page - 1) * limit;

        let search_pattern = search_term.map(|search| format!("%{}%", search));

        let mut query = users::table.into_boxed();
        let mut count_query = users::table.into_boxed();

        if let Some(ref pattern) = search_pattern {
            let search_filter = users::name
                .ilike(pattern)
                .or(users::email.ilike(pattern))
                .or(users::username.ilike(pattern));

            query = query.filter(search_filter.clone());
            count_query = count_query.filter(search_filter);
        }

        if let Some(user_role) = role_filter {
            query = query.filter(users::role.eq(user_role));
            count_query = count_query.filter(users::role.eq(user_role));
        }

        if let Some(is_verified) = verified_filter {
            query = query.filter(users::verified.eq(is_verified));
            count_query = count_query.filter(users::verified.eq(is_verified));
        }

        let user_list = query
            .select(User::as_select())
            .limit(limit as i64)
            .offset(offset as i64)
            .order(users::created_at.desc())
            .load(&mut conn)?;

        let total_count: i64 = count_query.count().get_result(&mut conn)?;

        Ok((user_list, total_count))
    }

    pub fn verify_token(pool: &PgPool, token_str: &str) -> Result<(), ConfigError> {
        let mut conn = pool.get()?;
        let now = Utc::now().naive_utc();

        let target_user = users
            .filter(verification_token.eq(Some(token_str.to_string())))
            .filter(token_expires_at.gt(now))
            .first::<User>(&mut conn)
            .optional()?;

        if let Some(user) = target_user {
            diesel
                ::update(users.filter(id.eq(user.id)))
                .set((
                    verified.eq(true),
                    verification_token.eq::<Option<String>>(None),
                    token_expires_at.eq::<Option<NaiveDateTime>>(None),
                    updated_at.eq(now),
                ))
                .execute(&mut conn)?;
            Ok(())
        } else {
            Err(ConfigError::NotFound)
        }
    }

    pub fn add_verification_token(
        pool: &PgPool,
        user_id: Uuid,
        token: String,
        expires_at: NaiveDateTime
    ) -> Result<(), ConfigError> {
        let mut conn = pool.get()?;

        diesel
            ::update(users.filter(id.eq(user_id)))
            .set((
                verification_token.eq(Some(token)),
                token_expires_at.eq(Some(expires_at)),
                updated_at.eq(Utc::now().naive_utc()),
            ))
            .execute(&mut conn)?;

        Ok(())
    }

    pub fn update_user_password(
        pool: &PgPool,
        user_id: Uuid,
        new_hashed_password: String
    ) -> Result<(), ConfigError> {
        let mut conn = pool.get()?;

        diesel
            ::update(users.filter(id.eq(user_id)))
            .set((password.eq(new_hashed_password), updated_at.eq(Utc::now().naive_utc())))
            .execute(&mut conn)?;

        Ok(())
    }

    /// Update a user with partial data
    pub fn update_user(
        conn: &mut PgConnection,
        user_id: Uuid,
        update_data: UpdateUserRequest
    ) -> Result<User, ConfigError> {
        let now = Utc::now().naive_utc();

        // First get the current user to fill in missing fields
        let current_user = users
            .filter(id.eq(user_id))
            .first::<User>(conn)
            .optional()?
            .ok_or(ConfigError::NotFound)?;

        // Build the update with current values as defaults
        let result = diesel
            ::update(users.filter(id.eq(user_id)))
            .set((
                name.eq(update_data.name.unwrap_or(current_user.name)),
                email.eq(update_data.email.unwrap_or(current_user.email)),
                username.eq(update_data.username.unwrap_or(current_user.username)),
                password.eq(update_data.password.unwrap_or(current_user.password)),
                role.eq(update_data.role.unwrap_or(current_user.role)),
                verified.eq(update_data.verified.unwrap_or(current_user.verified)),
                updated_at.eq(update_data.updated_at.unwrap_or(now)),
            ))
            .get_result(conn)?;

        Ok(result)
    }

    /// More efficient update method using a helper struct
    pub fn update_user_efficient(
        pool: &PgPool,
        user_id: Uuid,
        update_data: UpdateUserRequest
    ) -> Result<User, ConfigError> {
        let mut conn = pool.get()?;
        let now = Utc::now().naive_utc();

        // First get the current user
        let current_user = users
            .filter(id.eq(user_id))
            .first::<User>(&mut conn)
            .optional()?
            .ok_or(ConfigError::NotFound)?;

        // Apply updates only to changed fields
        let updated_user = diesel
            ::update(users.filter(id.eq(user_id)))
            .set(
                &(UpdateUser {
                    name: update_data.name.unwrap_or(current_user.name),
                    email: update_data.email.unwrap_or(current_user.email),
                    username: update_data.username.unwrap_or(current_user.username),
                    password: update_data.password.unwrap_or(current_user.password),
                    verified: update_data.verified.unwrap_or(current_user.verified),
                    role: update_data.role.unwrap_or(current_user.role),
                    updated_at: now,
                })
            )
            .get_result(&mut conn)?;

        Ok(updated_user)
    }

    /// Delete a user by ID
    pub fn delete_user(pool: &PgPool, user_id: Uuid) -> Result<(), ConfigError> {
        let mut conn = pool.get()?;

        let deleted_rows = diesel::delete(users.filter(id.eq(user_id))).execute(&mut conn)?;

        if deleted_rows > 0 {
            Ok(())
        } else {
            Err(ConfigError::NotFound)
        }
    }

    /// Bulk delete users by IDs
    pub fn bulk_delete_users(pool: &PgPool, user_ids: &[Uuid]) -> Result<usize, ConfigError> {
        let mut conn = pool.get()?;

        let deleted_count = diesel::delete(users.filter(id.eq_any(user_ids))).execute(&mut conn)?;

        Ok(deleted_count)
    }

    /// Update user role for multiple users
    pub fn bulk_update_user_roles(
        pool: &PgPool,
        user_ids: &[Uuid],
        new_role: UserRole
    ) -> Result<usize, ConfigError> {
        let mut conn = pool.get()?;
        let now = Utc::now().naive_utc();

        let updated_count = diesel
            ::update(users.filter(id.eq_any(user_ids)))
            .set((role.eq(new_role), updated_at.eq(now)))
            .execute(&mut conn)?;

        Ok(updated_count)
    }

    /// Bulk verify users
    pub fn bulk_verify_users(pool: &PgPool, user_ids: &[Uuid]) -> Result<usize, ConfigError> {
        let mut conn = pool.get()?;
        let now = Utc::now().naive_utc();

        let updated_count = diesel
            ::update(users.filter(id.eq_any(user_ids)))
            .set((
                verified.eq(true),
                verification_token.eq::<Option<String>>(None),
                token_expires_at.eq::<Option<NaiveDateTime>>(None),
                updated_at.eq(now),
            ))
            .execute(&mut conn)?;

        Ok(updated_count)
    }

    /// Get users by role with pagination
    pub fn get_users_by_role_paginated(
        pool: &PgPool,
        user_role: UserRole,
        page: usize,
        limit: usize
    ) -> Result<(Vec<User>, i64), ConfigError> {
        let mut conn = pool.get()?;
        let offset = (page - 1) * limit;

        let user_list = users::table
            .filter(role.eq(user_role))
            .select(User::as_select())
            .limit(limit as i64)
            .offset(offset as i64)
            .order(users::created_at.desc())
            .load(&mut conn)?;

        let total_count: i64 = users::table
            .filter(role.eq(user_role))
            .count()
            .get_result(&mut conn)?;

        Ok((user_list, total_count))
    }

    /// Get unverified users that need token cleanup
    pub fn get_expired_unverified_users(pool: &PgPool) -> Result<Vec<User>, ConfigError> {
        let mut conn = pool.get()?;
        let now = Utc::now().naive_utc();

        let expired_users = users
            .filter(verified.eq(false))
            .filter(token_expires_at.lt(now))
            .filter(verification_token.is_not_null())
            .load::<User>(&mut conn)?;

        Ok(expired_users)
    }

    /// Clean up expired verification tokens
    pub fn cleanup_expired_tokens(pool: &PgPool) -> Result<usize, ConfigError> {
        let mut conn = pool.get()?;
        let now = Utc::now().naive_utc();

        let updated_count = diesel
            ::update(
                users
                    .filter(verified.eq(false))
                    .filter(token_expires_at.lt(now))
                    .filter(verification_token.is_not_null())
            )
            .set((
                verification_token.eq::<Option<String>>(None),
                token_expires_at.eq::<Option<NaiveDateTime>>(None),
                updated_at.eq(now),
            ))
            .execute(&mut conn)?;

        Ok(updated_count)
    }

    /// Get user statistics
    pub fn get_user_statistics(pool: &PgPool) -> Result<UserStatistics, ConfigError> {
        let mut conn = pool.get()?;

        let total_users: i64 = users::table.count().get_result(&mut conn)?;

        let verified_users: i64 = users::table
            .filter(verified.eq(true))
            .count()
            .get_result(&mut conn)?;

        let admin_users: i64 = users::table
            .filter(role.eq(UserRole::Admin))
            .count()
            .get_result(&mut conn)?;

        let moderator_users: i64 = users::table
            .filter(role.eq(UserRole::Moderator))
            .count()
            .get_result(&mut conn)?;

        let regular_users: i64 = users::table
            .filter(role.eq(UserRole::User))
            .count()
            .get_result(&mut conn)?;

        Ok(UserStatistics {
            total_users: total_users as usize,
            verified_users: verified_users as usize,
            unverified_users: (total_users - verified_users) as usize,
            admin_users: admin_users as usize,
            moderator_users: moderator_users as usize,
            regular_users: regular_users as usize,
        })
    }

    /// Advanced search with multiple filters
    pub fn advanced_search_users(
        pool: &PgPool,
        filters: AdvancedUserFilters,
        page: usize,
        limit: usize
    ) -> Result<(Vec<User>, i64), ConfigError> {
        let mut conn = pool.get()?;
        let offset = (page - 1) * limit;

        let mut query = users::table.into_boxed();
        let mut count_query = users::table.into_boxed();

        // Apply search term filter
        if let Some(search_term) = &filters.search_term {
            let search_pattern = format!("%{}%", search_term);
            let search_filter = users::name
                .ilike(search_pattern.clone())
                .or(users::email.ilike(search_pattern.clone()))
                .or(users::username.ilike(search_pattern.clone()));

            query = query.filter(search_filter.clone());
            count_query = count_query.filter(search_filter);
        }

        // Apply role filter
        if let Some(user_roles) = &filters.roles {
            query = query.filter(users::role.eq_any(user_roles));
            count_query = count_query.filter(users::role.eq_any(user_roles));
        }

        // Apply verification filter
        if let Some(is_verified) = filters.verified {
            query = query.filter(users::verified.eq(is_verified));
            count_query = count_query.filter(users::verified.eq(is_verified));
        }

        // Apply date range filters
        if let Some(created_after) = filters.created_after {
            query = query.filter(users::created_at.ge(created_after));
            count_query = count_query.filter(users::created_at.ge(created_after));
        }

        if let Some(created_before) = filters.created_before {
            query = query.filter(users::created_at.le(created_before));
            count_query = count_query.filter(users::created_at.le(created_before));
        }

        // Apply sorting
        let query = match filters.sort_by.unwrap_or(UserSortBy::CreatedAt) {
            UserSortBy::CreatedAt => {
                if filters.sort_desc.unwrap_or(true) {
                    query.order(users::created_at.desc())
                } else {
                    query.order(users::created_at.asc())
                }
            }
            UserSortBy::Name => {
                if filters.sort_desc.unwrap_or(false) {
                    query.order(users::name.desc())
                } else {
                    query.order(users::name.asc())
                }
            }
            UserSortBy::Email => {
                if filters.sort_desc.unwrap_or(false) {
                    query.order(users::email.desc())
                } else {
                    query.order(users::email.asc())
                }
            }
        };

        let user_list = query
            .select(User::as_select())
            .limit(limit as i64)
            .offset(offset as i64)
            .load(&mut conn)?;

        let total_count: i64 = count_query.count().get_result(&mut conn)?;

        Ok((user_list, total_count))
    }
}
